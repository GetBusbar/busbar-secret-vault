// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::cred::{Cred, Held, SealedWrite};
use busbar_contract::abi::sdk::test_support::chip;
use std::task::Poll;

/// Observe output only after the SDK writes it to the host-owned output buffer.
pub fn material(value: Held<Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![0; value.len()];
    let (outcome, output) = chip::resolve_into(value, &mut bytes);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(output.secret.len, bytes.len());
    bytes
}

/// Stand in for the host's wire, without adding a production credential getter.
pub fn token(value: &Cred) -> Vec<u8> {
    let mut write = SealedWrite::message(value.field());
    let mut bytes = Vec::new();
    assert_eq!(
        chip::drive_sealed::<()>(&mut write, |part| {
            bytes.extend_from_slice(part);
            Poll::Ready(Ok(part.len()))
        }),
        Poll::Ready(Ok(()))
    );
    bytes
}

pub fn judge(
    path: &str,
    field: &str,
    url: &str,
    reply: Result<crate::Response, busbar_contract::abi::sdk::conn::ConnFailure>,
) -> busbar_contract::secret::SecretResult<Vec<u8>> {
    crate::judge(path, field, url, reply).map(material)
}

#[test]
fn opaque_selection_retries_a_short_host_output_without_partial_material() {
    let select = || match busbar_contract::abi::sdk::cred::select_json(
        Held::new(br#"{"data":{"data":{"k":"secret\u002dvalue"}}}"#.to_vec()),
        &["data", "data", "k"],
    )
    .unwrap()
    {
        busbar_contract::abi::sdk::cred::SelectedJson::Value(value) => value,
        _ => panic!("selected material"),
    };
    let mut short = [0; 3];
    let (outcome, output) = chip::resolve_into(select(), &mut short);
    assert_eq!(outcome, Outcome::Failed);
    assert_eq!(output.needed, 12);
    assert_eq!(short, [0; 3]);
    assert_eq!(material(select()), b"secret-value");
}
