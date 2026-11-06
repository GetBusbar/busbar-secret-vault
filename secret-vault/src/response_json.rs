// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The guarded JSON readers: Vault's reply and the open-time settings. Neither hands `serde_json`
//! a material-bearing string byte: serde reads a view of the document whose string contents are
//! masked (`x`, same length, so every position is the document's), and each string the reader keeps
//! is decoded from the real bytes into a buffer wiped when it is released.
//!
//! A reply is walked, not built: only `data.data.<field>` is kept, and every other value is
//! validated where it lies and dropped, so a reply under the 1 MiB cap cannot grow into a parsed
//! tree many times its size. A selected non-string value is written straight to the JSON text
//! `serde_json` prints for the parsed value (object keys sorted, the last of equal keys winning).
//!
//! Refusals report the guarded parser's current error and position without replaying the document.

use std::ops::Range;

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Unexpected, Visitor};
use serde_json::Value;
use zeroize::Zeroizing;

use super::Wiped;

/// What a parse filled a buffer with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// The document copy serde reads, before and after its strings are masked.
    View,
    /// A decoded object key.
    Key,
    /// A decoded string value, or a written value's JSON text.
    Value,
}

/// Where a parse reports each buffer it fills from the document, while that buffer is live. Tests
/// watch these to prove each one is wiped before it is freed; production passes [`Unwatched`].
pub(crate) trait Custody: Copy {
    /// `bytes`, the initialised start of a live buffer, hold document bytes of kind `what`.
    fn held(self, what: Held, bytes: &[u8]);
}

/// The production [`Custody`]: nothing is watched.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unwatched;

impl Custody for Unwatched {
    fn held(self, _: Held, _: &[u8]) {}
}

/// What a reply holds at `data.data.<field>` (the last of equal keys winning at every level).
pub(crate) enum Selected {
    /// `data.data` is absent or not an object.
    NoData,
    /// `data.data` is an object without the field.
    NoField,
    /// The field is JSON `null`.
    Null,
    /// The field is a string, decoded.
    Text(Zeroizing<String>),
    /// The field is another value: its JSON text, in a buffer of exactly its length.
    Rendered(Zeroizing<Vec<u8>>),
}

/// The accepted open-time configuration keys.
const CONFIG_FIELDS: &[&str] = &["addr", "token", "ca_cert_pem", "timeout_secs"];

/// `data.data.<field>` of a Vault reply `body`.
pub(crate) fn select<C: Custody>(body: &[u8], field: &str, custody: C) -> Result<Selected, String> {
    let view = masked(body, custody);
    let doc = Doc {
        body,
        view: &view,
        custody,
    };
    let mut de = serde_json::Deserializer::from_slice(&view);
    let walk = Walk {
        doc,
        field,
        depth: 0,
    };
    walk.deserialize(&mut de)
        .and_then(|selected| de.end().map(|()| selected))
        .map_err(|e| e.to_string())
}

/// The open-time settings `body` as a tree, checked against `VaultConfig`
/// (`deny_unknown_fields`; `addr` a string and `token` present; `ca_cert_pem` a string or null and
/// `timeout_secs` a `u64` when given; each key at most once), with `serde_json`'s texts. Config
/// strings have the same custody as a reply's.
pub(crate) fn parse_config<C: Custody>(body: &[u8], custody: C) -> Result<Wiped, String> {
    let view = masked(body, custody);
    let doc = Doc {
        body,
        view: &view,
        custody,
    };
    let mut de = serde_json::Deserializer::from_slice(&view);
    Config(doc)
        .deserialize(&mut de)
        .and_then(|tree| de.end().map(|()| tree))
        .map_err(|e| e.to_string())
}

/// A copy of `body` with every byte inside a string (escapes included) replaced by `x`.
fn masked<C: Custody>(body: &[u8], custody: C) -> Zeroizing<Vec<u8>> {
    let mut view = Zeroizing::new(body.to_vec());
    custody.held(Held::View, &view);
    let mut inside = false;
    let mut escaped = false;
    for byte in view.iter_mut() {
        if !inside {
            inside = *byte == b'"';
        } else if !escaped && *byte == b'"' {
            inside = false;
        } else {
            let escape = !escaped && *byte == b'\\';
            *byte = b'x';
            escaped = escape;
        }
    }
    view
}

/// `serde_json`'s control-character refusal.
const CONTROL: &str = "control character (\\u0000-\\u001F) found while parsing a string";

/// The document a reader walks: its real bytes, the masked view serde reads, and the custody
/// every buffer filled from it is reported to.
#[derive(Clone, Copy)]
struct Doc<'a, C> {
    body: &'a [u8],
    view: &'a [u8],
    custody: C,
}

impl<'a, C: Custody> Doc<'a, C> {
    /// The real bytes of the string serde read as `masked` from the view.
    fn raw<E: Error>(self, masked: &str) -> Result<&'a [u8], E> {
        (masked.as_ptr() as usize)
            .checked_sub(self.view.as_ptr() as usize)
            .and_then(|start| self.body.get(start..start.checked_add(masked.len())?))
            .ok_or_else(|| E::custom("invalid JSON string span"))
    }

    /// The string serde read as `masked`, decoded from the real bytes into a guarded buffer.
    fn decoded<E: Error>(self, masked: &str, what: Held) -> Result<Zeroizing<String>, E> {
        let raw = self.raw::<E>(masked)?;
        let mut decoded = Zeroizing::new(String::with_capacity(raw.len()));
        let result = decode(raw, &mut *decoded);
        self.custody.held(what, decoded.as_bytes());
        result.map_err(E::custom)?;
        Ok(decoded)
    }

    /// Refuse the string serde read as `masked` unless it decodes, copying it nowhere.
    fn validated<E: Error>(self, masked: &str) -> Result<(), E> {
        let raw = self.raw::<E>(masked)?;
        decode(raw, &mut Discard).map_err(E::custom)
    }
}

/// A reply value walked toward `data.data.<field>`: the root at `depth` 0, `data` at 1 and
/// `data.data` at 2.
struct Walk<'a, C> {
    doc: Doc<'a, C>,
    field: &'a str,
    depth: u8,
}

impl<'de, C: Custody> DeserializeSeed<'de> for Walk<'_, C> {
    type Value = Selected;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Selected, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Walk<'_, C> {
    type Value = Selected;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<Selected, E> {
        Ok(Selected::NoData)
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<Selected, E> {
        Ok(Selected::NoData)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<Selected, E> {
        Ok(Selected::NoData)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<Selected, E> {
        Ok(Selected::NoData)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<Selected, E> {
        Ok(Selected::NoData)
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Selected, E> {
        self.doc.validated::<E>(value)?;
        Ok(Selected::NoData)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Selected, A::Error> {
        while seq.next_element_seed(Skip(self.doc))?.is_some() {}
        Ok(Selected::NoData)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Selected, A::Error> {
        let fields = self.depth >= 2;
        let wanted = if fields { self.field } else { "data" };
        let mut found = if fields {
            Selected::NoField
        } else {
            Selected::NoData
        };
        while let Some(key) = map.next_key_seed(AnyKey(self.doc))? {
            let ObjectKey::Text(key) = key else {
                map.next_value_seed(NumberText)?;
                return Ok(Selected::NoData);
            };
            if key.as_str() != wanted {
                map.next_value_seed(Skip(self.doc))?;
            } else if fields {
                found = map.next_value_seed(Pick(self.doc))?;
            } else {
                found = map.next_value_seed(Walk {
                    doc: self.doc,
                    field: self.field,
                    depth: self.depth + 1,
                })?;
            }
        }
        Ok(found)
    }
}

/// The selected field's value.
struct Pick<'a, C>(Doc<'a, C>);

impl<C: Custody> Pick<'_, C> {
    /// `value` (a scalar) as its JSON text.
    fn written<T: serde::Serialize, E: Error>(self, value: &T) -> Result<Selected, E> {
        let mut out = Guarded::empty(self.0.custody);
        out.json::<T, E>(value)?;
        Ok(Selected::Rendered(out.exact()))
    }
}

impl<'de, C: Custody> DeserializeSeed<'de> for Pick<'_, C> {
    type Value = Selected;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Selected, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Pick<'_, C> {
    type Value = Selected;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<Selected, E> {
        Ok(Selected::Null)
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Selected, E> {
        self.written(&value)
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Selected, E> {
        self.written(&value)
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Selected, E> {
        self.written(&value)
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Selected, E> {
        self.written(&value)
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Selected, E> {
        Ok(Selected::Text(self.0.decoded::<E>(value, Held::Value)?))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Selected, A::Error> {
        let mut out = Guarded::empty(self.0.custody);
        Render {
            doc: self.0,
            out: &mut out,
            lead: b"",
        }
        .visit_seq(seq)?;
        Ok(Selected::Rendered(out.exact()))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Selected, A::Error> {
        let mut out = Guarded::empty(self.0.custody);
        Render {
            doc: self.0,
            out: &mut out,
            lead: b"",
        }
        .visit_map(map)?;
        Ok(Selected::Rendered(out.exact()))
    }
}

/// One member of an object being written: its name's decoded bytes and its value's JSON text, as
/// ranges of the object's arena.
struct Member {
    name: Range<usize>,
    value: Range<usize>,
}

/// A value written as JSON text onto `out`, after `lead` (the separator from the value before it).
struct Render<'a, 'o, C: Custody> {
    doc: Doc<'a, C>,
    out: &'o mut Guarded<C>,
    lead: &'static [u8],
}

impl<C: Custody> Render<'_, '_, C> {
    /// Write scalar `value`.
    fn scalar<T: serde::Serialize + ?Sized, E: Error>(self, value: &T) -> Result<(), E> {
        let Self { out, .. } = self;
        out.json(value)
    }
}

impl<'de, C: Custody> DeserializeSeed<'de> for Render<'_, '_, C> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        let Self { doc, out, lead } = self;
        out.push(lead);
        de.deserialize_any(Render {
            doc,
            out,
            lead: b"",
        })
    }
}

impl<'de, C: Custody> Visitor<'de> for Render<'_, '_, C> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        self.scalar(&())
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<(), E> {
        self.scalar(&value)
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<(), E> {
        let text = self.doc.decoded::<E>(value, Held::Value)?;
        self.scalar(text.as_str())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let Self { doc, out, .. } = self;
        out.push(b"[");
        let mut lead: &'static [u8] = b"";
        while seq
            .next_element_seed(Render {
                doc,
                out: &mut *out,
                lead,
            })?
            .is_some()
        {
            lead = b",";
        }
        out.push(b"]");
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Self { doc, out, .. } = self;
        let mut arena = Guarded::empty(doc.custody);
        let mut members = Vec::new();
        while let Some(key) = map.next_key_seed(AnyKey(doc))? {
            let ObjectKey::Text(key) = key else {
                let number = map.next_value_seed(NumberText)?;
                return out.json::<_, A::Error>(&number);
            };
            let start = arena.len();
            arena.push(key.as_bytes());
            let name = start..arena.len();
            map.next_value_seed(Render {
                doc,
                out: &mut arena,
                lead: b"",
            })?;
            members.push(Member {
                value: name.end..arena.len(),
                name,
            });
        }
        // The parsed value's map order (byte order of the keys), the last of equal keys winning:
        // the sort is stable, so the last of a run of equal names is the document's last.
        members.sort_by(|a, b| arena.get(&a.name).cmp(arena.get(&b.name)));
        out.push(b"{");
        let mut lead: &[u8] = b"";
        for (i, member) in members.iter().enumerate() {
            let name = arena.get(&member.name);
            if members
                .get(i + 1)
                .is_some_and(|next| arena.get(&next.name) == name)
            {
                continue;
            }
            out.push(lead);
            lead = b",";
            out.json::<str, A::Error>(std::str::from_utf8(name).map_err(A::Error::custom)?)?;
            out.push(b":");
            out.push(arena.get(&member.value));
        }
        out.push(b"}");
        Ok(())
    }
}

/// A buffer whose growth wipes the allocation it leaves, so no partial copy of what it holds is
/// freed unwiped; dropping it wipes it too.
struct Guarded<C: Custody>(Zeroizing<Vec<u8>>, C);

impl<C: Custody> Guarded<C> {
    fn empty(custody: C) -> Self {
        Self(Zeroizing::new(Vec::new()), custody)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, range: &Range<usize>) -> &[u8] {
        self.0.get(range.clone()).unwrap_or_default()
    }

    fn push(&mut self, bytes: &[u8]) {
        let needed = self.0.len().saturating_add(bytes.len());
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(
                needed.max(self.0.capacity().saturating_mul(2)),
            ));
            grown.extend_from_slice(&self.0);
            self.1.held(Held::Value, &self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
    }

    /// Write `value` as `serde_json` writes it.
    fn json<T: serde::Serialize + ?Sized, E: Error>(&mut self, value: &T) -> Result<(), E> {
        serde_json::to_writer(&mut *self, value).map_err(E::custom)
    }

    /// The text in a buffer of exactly its length; this one is reported to `custody`, then wiped.
    fn exact(self) -> Zeroizing<Vec<u8>> {
        let mut text = Vec::with_capacity(self.0.len());
        text.extend_from_slice(&self.0);
        self.1.held(Held::Value, &text);
        Zeroizing::new(text)
    }
}

impl<C: Custody> Drop for Guarded<C> {
    fn drop(&mut self) {
        self.1.held(Held::Value, &self.0);
    }
}

impl<C: Custody> std::io::Write for Guarded<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.push(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Any value, validated and dropped where it lies: nothing of it is copied.
struct Skip<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Skip<'_, C> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Skip<'_, C> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<(), E> {
        if self.0.raw::<E>(value).is_err() && value == "$serde_json::private::Number" {
            // A synthetic number key, not bytes from a JSON string in the document.
            Ok(())
        } else {
            self.0.validated(value)
        }
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<(), E> {
        Err(E::custom("unexpected non-borrowed JSON string"))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<(), E> {
        // Only serde_json's already-validated numeric token is owned; masked document
        // strings are borrowed and validated above, without decoding allocations.
        drop(Zeroizing::new(value));
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Skip(self.0))?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(Skip(self.0))?.is_some() {
            map.next_value_seed(Skip(self.0))?;
        }
        Ok(())
    }
}

/// An actual object key, or serde_json's synthetic arbitrary-precision number tag.
/// Actual keys always borrow from the masked view. Checking that provenance before the tag
/// prevents a document key with serde's private spelling from impersonating a number.
enum ObjectKey {
    Text(Zeroizing<String>),
    Number,
}

struct AnyKey<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for AnyKey<'_, C> {
    type Value = ObjectKey;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<ObjectKey, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for AnyKey<'_, C> {
    type Value = ObjectKey;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an object key or a serde_json number tag")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<ObjectKey, E> {
        if self.0.raw::<E>(value).is_ok() {
            self.0.decoded(value, Held::Key).map(ObjectKey::Text)
        } else if value == "$serde_json::private::Number" {
            Ok(ObjectKey::Number)
        } else {
            Err(E::custom("invalid JSON string span"))
        }
    }
}

/// Only the synthetic number map supplies an owned string. JSON strings still use the guarded
/// decoder above; this numeric token has already been validated by serde_json's lexer.
struct NumberText;

impl<'de> DeserializeSeed<'de> for NumberText {
    type Value = serde_json::Number;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_string(self)
    }
}

impl<'de> Visitor<'de> for NumberText {
    type Value = serde_json::Number;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("serde_json's numeric token")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        value.parse().map_err(E::custom)
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        self.visit_str(&Zeroizing::new(value))
    }
}

/// An object key, decoded.
struct Key<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Key<'_, C> {
    type Value = Zeroizing<String>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Key<'_, C> {
    type Value = Zeroizing<String>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Zeroizing<String>, E> {
        self.0.decoded(value, Held::Key)
    }
}

/// The open-time settings object.
struct Config<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Config<'_, C> {
    type Value = Wiped;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Wiped, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Config<'_, C> {
    type Value = Wiped;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("struct VaultConfig")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Wiped, E> {
        let text = self.0.decoded::<E>(value, Held::Value)?;
        Err(E::invalid_type(Unexpected::Str(text.as_str()), &self))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Wiped, A::Error> {
        let mut tree = Wiped::object();
        while let Some(mut key) = map.next_key_seed(Key(self.0))? {
            let Some(&name) = CONFIG_FIELDS.iter().find(|name| **name == key.as_str()) else {
                return Err(A::Error::unknown_field(key.as_str(), CONFIG_FIELDS));
            };
            if tree.has(name) {
                return Err(A::Error::duplicate_field(name));
            }
            let mut value = match name {
                "addr" => map.next_value_seed(Text(self.0))?,
                "ca_cert_pem" => map.next_value_seed(OptionalText(self.0))?,
                "timeout_secs" => map.next_value_seed(Seconds(self.0))?,
                _ => map.next_value_seed(Tree(self.0))?,
            };
            tree.put(&mut key, &mut value.0);
        }
        for name in ["addr", "token"] {
            if !tree.has(name) {
                return Err(A::Error::missing_field(name));
            }
        }
        Ok(tree)
    }
}

/// A string setting (`addr`), decoded.
struct Text<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Text<'_, C> {
    type Value = Wiped;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Wiped, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Text<'_, C> {
    type Value = Wiped;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Wiped, E> {
        let mut text = self.0.decoded::<E>(value, Held::Value)?;
        Ok(Wiped(Value::String(std::mem::take(&mut *text))))
    }
}

/// An optional string setting (`ca_cert_pem`): a string, or `null` for none.
struct OptionalText<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for OptionalText<'_, C> {
    type Value = Wiped;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Wiped, D::Error> {
        de.deserialize_option(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for OptionalText<'_, C> {
    type Value = Wiped;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("option")
    }

    fn visit_none<E: Error>(self) -> Result<Wiped, E> {
        Ok(Wiped(Value::Null))
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Wiped, D::Error> {
        Text(self.0).deserialize(de)
    }
}

/// The `timeout_secs` setting: an unsigned integer number of seconds.
struct Seconds<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Seconds<'_, C> {
    type Value = Wiped;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Wiped, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Seconds<'_, C> {
    type Value = Wiped;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("u64")
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Wiped, E> {
        Ok(Wiped(Value::from(value)))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Wiped, E> {
        match u64::try_from(value) {
            Ok(value) => Ok(Wiped(Value::from(value))),
            Err(_) => Err(E::invalid_value(Unexpected::Signed(value), &self)),
        }
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Wiped, E> {
        let text = self.0.decoded::<E>(value, Held::Value)?;
        Err(E::invalid_type(Unexpected::Str(text.as_str()), &self))
    }
}

/// Any value, kept whole (the token's reference).
struct Tree<'a, C>(Doc<'a, C>);

impl<'de, C: Custody> DeserializeSeed<'de> for Tree<'_, C> {
    type Value = Wiped;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Wiped, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Tree<'_, C> {
    type Value = Wiped;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<Wiped, E> {
        Ok(Wiped(Value::Null))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Wiped, E> {
        Ok(Wiped(Value::Bool(value)))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Wiped, E> {
        Ok(Wiped(Value::from(value)))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Wiped, E> {
        Ok(Wiped(Value::from(value)))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Wiped, E> {
        Ok(Wiped(Value::from(value)))
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Wiped, E> {
        let mut text = self.0.decoded::<E>(value, Held::Value)?;
        Ok(Wiped(Value::String(std::mem::take(&mut *text))))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Wiped, A::Error> {
        let mut items = Wiped(Value::Array(Vec::new()));
        while let Some(mut item) = seq.next_element_seed(Tree(self.0))? {
            items.push(&mut item.0);
        }
        Ok(items)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Wiped, A::Error> {
        let mut tree = Wiped::object();
        while let Some(key) = map.next_key_seed(AnyKey(self.0))? {
            let ObjectKey::Text(mut key) = key else {
                return Ok(Wiped(Value::Number(map.next_value_seed(NumberText)?)));
            };
            let mut value = map.next_value_seed(Tree(self.0))?;
            tree.put(&mut key, &mut value.0);
        }
        Ok(tree)
    }
}

/// Where [`decode`] writes a string's characters.
trait Sink {
    fn put(&mut self, text: &str);
}

impl Sink for String {
    fn put(&mut self, text: &str) {
        self.push_str(text);
    }
}

/// A [`Sink`] that keeps nothing: validation alone.
struct Discard;

impl Sink for Discard {
    fn put(&mut self, _: &str) {}
}

/// Decode the JSON string contents `raw` (between its quotes) into `out`, refusing what
/// `serde_json` refuses, in its words. `out` never needs more than `raw.len()` bytes.
fn decode(mut raw: &[u8], out: &mut impl Sink) -> Result<(), &'static str> {
    // serde validates UTF-8 only after the closing quote, after judging every escape.
    let mut invalid_unicode = false;
    while !raw.is_empty() {
        let end = raw
            .iter()
            .position(|byte| *byte == b'\\' || *byte < 0x20)
            .unwrap_or(raw.len());
        match std::str::from_utf8(&raw[..end]) {
            Ok(text) => out.put(text),
            Err(_) => invalid_unicode = true,
        }
        raw = &raw[end..];
        let Some((&first, tail)) = raw.split_first() else {
            break;
        };
        if first != b'\\' {
            return Err(CONTROL);
        }
        let Some((&escape, tail)) = tail.split_first() else {
            return Err("EOF while parsing a string");
        };
        raw = tail;
        let ch = match escape {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = hex4(&mut raw)?;
                let code = if (0xD800..0xDC00).contains(&first) {
                    raw = raw
                        .strip_prefix(b"\\u")
                        .ok_or("unexpected end of hex escape")?;
                    let low = hex4(&mut raw)?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return Err("lone leading surrogate in hex escape");
                    }
                    0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00)
                } else {
                    first
                };
                char::from_u32(code).ok_or("lone leading surrogate in hex escape")?
            }
            _ => return Err("invalid escape"),
        };
        out.put(ch.encode_utf8(&mut [0; 4]));
    }
    if invalid_unicode {
        Err("invalid unicode code point")
    } else {
        Ok(())
    }
}

/// The four hex digits of a `\u` escape at the start of `raw`, consumed.
fn hex4(raw: &mut &[u8]) -> Result<u32, &'static str> {
    let digits = raw.get(..4).ok_or("EOF while parsing a string")?;
    let mut value = 0;
    for byte in digits {
        value = value * 16 + char::from(*byte).to_digit(16).ok_or("invalid escape")?;
    }
    *raw = &raw[4..];
    Ok(value)
}
