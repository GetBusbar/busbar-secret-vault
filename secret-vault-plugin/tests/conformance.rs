// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE VAULT PLUGIN, BOTH DOORS, ONE TABLE** — the Vault secret plugin's linked + dropped-in
//! conformance on the secret kind's memory ABI (THE DESIGN §2 "Each plugin tests itself", §11.4),
//! run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, through the
//! loader's `load_linked`) and DROPPED IN (this crate's built cdylib, `dlopen`ed by the loader's
//! `load_dropped`, which resolves `busbar_plugin_door` and validates the door). Each is bound to a
//! real dispatcher and driven over the same script through the secret kind's table: `validate`
//! over 1.5.5's config refusals, `open` without and with the kernel-resolved token, `resolve` over
//! every malformed reference and a well-formed one, `release` of a lease never granted, `refresh`
//! refused and accepted, `tick`, `close`. The two transcripts must be equal.
//!
//! The dropped-in door is admitted against the Statement rendering `busbar-plugin-pack` signs into
//! its manifest (`rendering_of_library`, read off the built cdylib); the linked row states its own
//! (`LinkedRow::of`). The two renderings must be equal byte for byte.
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused; a manifest stating
//! another kind, or 1.5.5's secret ABI version, is refused before `dlopen` (a Statement mismatch);
//! the dropped-in door opened over ANOTHER config answers a different transcript (so the equality
//! is not vacuous); an `open` with no token material is refused. A missing cdylib PANICS — this test
//! IS the dropped-in door's proof, and never skips.
//!
//! NOT YET HELD HERE: the undeclared-need and cross-instance `ConnId` arms need this plugin's need
//! declaration and its resolve over the SDK's `exchange()`; the plugin declares no need yet, so no
//! instance is lent a connector and the well-formed resolve answers UNAVAILABLE naming that — the
//! same through both doors. The secret axis (`SecretRows`) that would open the plugin by module name through the
//! registry is WIRE-SECRET's; this test drives the table through the loader's typed `Plugin`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_library, Bind, Called,
    DispatchConfig, Dispatcher, Frame, LinkedRow, LoadError, NoSink, Plugin, NO_BLOB,
};

/// The token the kernel resolved; no transcript line may carry it.
const TOKEN: &str = "s.conformance-token";

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_secret_vault_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-secret-vault-plugin cdylib ({file}) is not built"))
}

/// The Statement rendering the signed manifest states for the dropped-in image, as
/// `busbar-plugin-pack` reads it off the built cdylib.
fn stated() -> Vec<u8> {
    rendering_of_library(&cdylib())
        .expect("the cdylib's Statement renders")
        .expect("the cdylib exports busbar_plugin_door")
}

/// [`stated`] with head words (0 mechanism version, 1 kind, 2 kind ABI, after the magic) replaced.
fn stating(words: &[(usize, u32)]) -> Vec<u8> {
    let mut r = stated();
    for &(word, value) in words {
        let at = RENDERING_MAGIC.len() + 4 * word;
        r[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    r
}

/// The process's dispatcher, as the composition root builds one.
fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }))
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("vault"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn linked(d: &Dispatcher) -> Plugin<Secret> {
    let row = LinkedRow::of(busbar_secret_vault::door::door).expect("the linked row states");
    load_linked::<Secret>(&row, bind(d)).expect("the linked door loads")
}

fn dropped(d: &Dispatcher) -> Plugin<Secret> {
    load_dropped::<Secret>(&cdylib(), &stated(), bind(d)).expect("the dropped-in door loads")
}

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: busbar_contract::abi::mechanism::call::BLOB_SECRET,
    }
}

/// A call's answer as the transcript spells it: outcome, error text, and whether a lease came back.
fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn validate(p: &Plugin<Secret>, settings: &str) -> String {
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings.as_bytes()),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    spelled(&p.call(lc::VALIDATE, &mut f))
}

fn open(p: &Plugin<Secret>, settings: &str, token: Option<&str>) -> String {
    let secrets: Vec<Blob> = token.map(|t| octets(t.as_bytes())).into_iter().collect();
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: json(settings.as_bytes()),
            secrets: secrets.as_ptr(),
            secrets_len: secrets.len(),
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    spelled(&p.call(lc::OPEN, &mut f))
}

fn refresh(p: &Plugin<Secret>, settings: &str, token: &str) -> String {
    let secrets = [octets(token.as_bytes())];
    let mut f = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: json(settings.as_bytes()),
            secrets: secrets.as_ptr(),
            secrets_len: secrets.len(),
        },
        out_head(),
    );
    spelled(&p.call(lc::REFRESH, &mut f))
}

fn resolve(p: &Plugin<Secret>, settings: &str) -> String {
    let mut f = Frame::new(
        ResolveIn {
            head: in_head(),
            settings: json(settings.as_bytes()),
        },
        ResolveOut {
            head: out_head(),
            secret: NO_BLOB,
            error_kind: 0,
            _reserved: 0,
        },
    );
    let c = p.call(secret::slot::RESOLVE, &mut f);
    format!("{} kind={}", spelled(&c), f.out.error_kind)
}

fn release(p: &Plugin<Secret>, lease: u64) -> String {
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    spelled(&p.call(lc::RELEASE, &mut f))
}

fn tick(p: &Plugin<Secret>) -> String {
    let mut f = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 7,
        },
    );
    let c = p.call(lc::TICK, &mut f);
    format!("{} next={}", spelled(&c), f.out.next_tick_ns)
}

fn close(p: &Plugin<Secret>) -> String {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    spelled(&p.call(lc::CLOSE, &mut f))
}

const GOOD: &str = r#"{"addr":"http://vault.internal:8200/","token":{"env":"VAULT_TOKEN"}}"#;

/// What one door does, as one comparable transcript.
fn transcript(p: &Plugin<Secret>, settings: &str) -> serde_json::Value {
    let validated: Vec<String> = [
        "",
        "  \n",
        "{ this is not json",
        r#"{"addr":"http://v"}"#,
        r#"{"addr":"http://v","token":"t","tls":true}"#,
        settings,
    ]
    .iter()
    .map(|s| validate(p, s))
    .collect();
    let refused_open = open(p, settings, None);
    let opened = open(p, settings, Some(TOKEN));
    let resolved: Vec<String> = [
        r#"{"field":"api_key"}"#,
        r#"{"path":"kv/data/openai"}"#,
        r#"{"path":"kv/data/openai#"}"#,
        r#"{"path":"kv/data/openai","field":""}"#,
        "[1]",
        r#"{"path":"kv/data/openai#api_key"}"#,
    ]
    .iter()
    .map(|s| resolve(p, s))
    .collect();
    serde_json::json!({
        "name": p.name(),
        "kind": format!("{:?}", p.kind()),
        "max_inflight": p.max_inflight(),
        "validate": validated,
        "open_without_token": refused_open,
        "open": opened,
        "open_again": open(p, settings, Some(TOKEN)),
        "resolve": resolved,
        "release_unknown": release(p, 42),
        "refresh_bad": refresh(p, "{}", TOKEN),
        "refresh": refresh(p, settings, TOKEN),
        "tick": tick(p),
        "close": close(p),
    })
}

/// The plugin answers as ONE plugin through either door, and the same image over another config
/// does not compare equal.
#[test]
fn the_linked_and_the_dropped_in_vault_plugin_are_one_plugin() {
    assert_eq!(
        LinkedRow::of(busbar_secret_vault::door::door)
            .expect("the linked row states")
            .statement,
        stated(),
        "the linked and the dropped-in door state different Statements"
    );
    let d = dispatcher();
    let linked = transcript(&linked(&d), GOOD);
    let dropped_in = transcript(&dropped(&d), GOOD);
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    let all = linked.to_string();
    assert!(
        !all.contains(TOKEN),
        "a transcript carries the token: {all}"
    );
    assert_eq!(linked["name"], busbar_secret_vault::NAME);
    assert_eq!(linked["kind"], "Secret");
    assert_eq!(linked["max_inflight"], 64);
    let mut validated = linked["validate"].clone();
    let unknown = validated[4].as_str().unwrap().to_string();
    assert!(
        unknown.starts_with("Failed lease=false invalid hashicorp-vault plugin config: unknown field `tls`, expected one of `addr`, `token`, `ca_cert_pem`, `timeout_secs` at line 1 column "),
        "{unknown}"
    );
    validated[4] = "UNKNOWN-FIELD".into();
    assert_eq!(
        validated,
        serde_json::json!([
            "Failed lease=false hashicorp-vault plugin requires config (addr, token); none provided",
            "Failed lease=false hashicorp-vault plugin requires config (addr, token); none provided",
            "Failed lease=false invalid hashicorp-vault plugin config: key must be a string at line 1 column 3",
            "Failed lease=false invalid hashicorp-vault plugin config: missing field `token` at line 1 column 19",
            "UNKNOWN-FIELD",
            "Ready lease=false ",
        ])
    );
    assert_eq!(
        linked["open_without_token"],
        "Failed lease=false invalid hashicorp-vault plugin config: `token` resolved to no secret material"
    );
    assert_eq!(linked["open"], "Ready lease=false ");
    assert_eq!(
        linked["open_again"], "Refused lease=false ",
        "one open per instance"
    );
    let url = "http://vault.internal:8200/v1/kv/data/openai";
    let mut resolved = linked["resolve"].clone();
    let not_object = resolved[4].as_str().unwrap().to_string();
    assert!(
        not_object.starts_with("Failed lease=false secret settings are not a JSON object: invalid type: sequence, expected a map")
            && not_object.ends_with(" kind=4"),
        "{not_object}"
    );
    resolved[4] = "NOT-AN-OBJECT".into();
    assert_eq!(
        resolved,
        serde_json::json!([
            "Failed lease=false missing or non-string `path` in secret reference settings kind=4",
            "Failed lease=false vault secret reference must name a field to extract: either add a `field` key, or suffix `path` with `#<field>` (e.g. \"kv/data/openai#api_key\"); got path \"kv/data/openai\" kind=4",
            "Failed lease=false vault secret reference must name a field to extract: either add a `field` key, or suffix `path` with `#<field>` (e.g. \"kv/data/openai#api_key\"); got path \"kv/data/openai#\" kind=4",
            "Failed lease=false `field` in secret reference settings must not be empty kind=4",
            "NOT-AN-OBJECT",
            format!("Failed lease=false request to Vault ({url}) failed: error sending request for url ({url}) kind=2"),
        ])
    );
    assert_eq!(linked["release_unknown"], "Refused lease=false ");
    assert!(
        linked["refresh_bad"]
            .as_str()
            .unwrap()
            .starts_with("Failed lease=false invalid hashicorp-vault plugin config: missing field"),
        "{}",
        linked["refresh_bad"]
    );
    assert_eq!(linked["refresh"], "Ready lease=false ");
    assert_eq!(linked["tick"], "Ready lease=false  next=0");
    assert_eq!(linked["close"], "Ready lease=false ");

    // RED: the same image opened over ANOTHER config answers another transcript.
    let other = transcript(
        &dropped(&d),
        r#"{"addr":"https://elsewhere:8200","token":{"env":"VAULT_TOKEN"}}"#,
    );
    assert_ne!(
        other, linked,
        "a door over another config must not compare equal"
    );
    assert_eq!(
        other["validate"].as_array().unwrap()[..5],
        linked["validate"].as_array().unwrap()[..5]
    );
}

/// RED: the door asked for as another kind is refused, by either origin.
#[test]
fn a_wrong_kind_is_refused() {
    let d = dispatcher();
    let row = LinkedRow::of(busbar_secret_vault::door::door).expect("the linked row states");
    let err =
        load_linked::<Export>(&row, bind(&d)).expect_err("a secret door is not an export door");
    let said = format!("{err:?}");
    assert!(said.contains("Secret") || said.contains("Kind"), "{said}");

    let as_export = stating(&[
        (1, KindCode::Export as u32),
        (2, busbar_contract::abi::export::ABI_VERSION),
    ]);
    let err = load_dropped::<Export>(&cdylib(), &as_export, bind(&d))
        .expect_err("the dropped-in secret door is not an export door");
    assert!(!matches!(err, LoadError::ManifestKind { .. }), "{err:?}");
}

/// RED: a manifest whose statement disagrees with what is asked is refused before `dlopen`.
#[test]
fn a_statement_mismatch_is_refused() {
    let d = dispatcher();
    let err = load_dropped::<Secret>(
        &cdylib(),
        &stating(&[(1, KindCode::Export as u32)]),
        bind(&d),
    )
    .expect_err("a manifest stating another kind is refused");
    assert!(matches!(err, LoadError::ManifestKind { .. }), "{err:?}");

    // 1.5.5's secret ABI was v1: a manifest stating it is refused (THE DESIGN §11.8).
    let err = load_dropped::<Secret>(
        &cdylib(),
        &stating(&[(2, secret::ABI_VERSION - 1)]),
        bind(&d),
    )
    .expect_err("a manifest stating 1.5.5's secret ABI is refused");
    assert!(matches!(err, LoadError::ManifestKindAbi { .. }), "{err:?}");

    let err = load_dropped::<Secret>(&cdylib(), &stating(&[(0, MECHANISM_VERSION + 1)]), bind(&d))
        .expect_err("a manifest stating another mechanism is refused");
    assert!(
        matches!(err, LoadError::ManifestMechanism { .. }),
        "{err:?}"
    );
}

/// RED: a wrong config never opens, and an unopened instance serves no resolve.
#[test]
fn a_wrong_config_never_opens() {
    let d = dispatcher();
    for p in [linked(&d), dropped(&d)] {
        assert!(open(&p, r#"{"addr":1,"token":"t"}"#, Some(TOKEN)).starts_with("Failed"));
        assert!(!p.is_open());
        assert!(resolve(&p, r#"{"path":"kv/data/x#k"}"#).starts_with("Refused"));
    }
}
