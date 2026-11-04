// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

pub(super) fn parse(body: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = serde_json::Value::deserialize(Observe(&mut deserializer))?;
    deserializer.end()?;
    Ok(value)
}

struct Observe<T>(T);

macro_rules! forward_deserialize {
    ($($name:ident $(($($arg:ident: $ty:ty),*))?),* $(,)?) => {
        $(fn $name<V: Visitor<'de>>(self, $($($arg: $ty,)*)? visitor: V) -> Result<V::Value, D::Error> {
            self.0.$name($($($arg,)*)? Observe(visitor))
        })*
    };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Observe<D> {
    type Error = D::Error;

    forward_deserialize! {
        deserialize_any, deserialize_bool,
        deserialize_i8, deserialize_i16, deserialize_i32, deserialize_i64, deserialize_i128,
        deserialize_u8, deserialize_u16, deserialize_u32, deserialize_u64, deserialize_u128,
        deserialize_f32, deserialize_f64, deserialize_char, deserialize_str, deserialize_string,
        deserialize_bytes, deserialize_byte_buf, deserialize_option, deserialize_unit,
        deserialize_unit_struct(name: &'static str),
        deserialize_newtype_struct(name: &'static str),
        deserialize_seq, deserialize_tuple(len: usize),
        deserialize_tuple_struct(name: &'static str, len: usize),
        deserialize_map, deserialize_struct(name: &'static str, fields: &'static [&'static str]),
        deserialize_enum(name: &'static str, variants: &'static [&'static str]),
        deserialize_identifier, deserialize_ignored_any,
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

macro_rules! forward_visit {
    ($($name:ident($ty:ty)),* $(,)?) => {
        $(fn $name<E: serde::de::Error>(self, value: $ty) -> Result<Self::Value, E> {
            self.0.$name(value)
        })*
    };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Observe<V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.expecting(f)
    }

    forward_visit! {
        visit_bool(bool), visit_i8(i8), visit_i16(i16), visit_i32(i32), visit_i64(i64), visit_i128(i128),
        visit_u8(u8), visit_u16(u16), visit_u32(u32), visit_u64(u64), visit_u128(u128),
        visit_f32(f32), visit_f64(f64), visit_char(char), visit_borrowed_str(&'de str),
        visit_string(String), visit_bytes(&[u8]), visit_borrowed_bytes(&'de [u8]), visit_byte_buf(Vec<u8>),
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        super::probe::watch("parser scratch", value.as_bytes());
        self.0.visit_str(value)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.0.visit_unit()
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.0.visit_none()
    }

    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.0.visit_some(Observe(de))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.0.visit_newtype_struct(Observe(de))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.0.visit_seq(Observe(access))
    }

    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.0.visit_map(Observe(access))
    }

    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.0.visit_enum(access)
    }
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Observe<S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        self.0.deserialize(Observe(de))
    }
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Observe<A> {
    type Error = A::Error;

    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.0.next_element_seed(Observe(seed))
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Observe<A> {
    type Error = A::Error;

    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.0.next_key_seed(Observe(seed))
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.0.next_value_seed(Observe(seed))
    }

    fn next_entry_seed<K: DeserializeSeed<'de>, V: DeserializeSeed<'de>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<(K::Value, V::Value)>, A::Error> {
        self.0.next_entry_seed(Observe(key), Observe(value))
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}
