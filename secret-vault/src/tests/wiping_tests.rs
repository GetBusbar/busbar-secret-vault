// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe owned token/body/parsed-value payloads through the actual client and judge.

#[allow(unsafe_code)]
#[path = "wipe_probe.rs"]
mod probe;

#[path = "serde_observer.rs"]
mod serde_observer;

#[allow(unsafe_code)]
#[path = "config_wiping_tests.rs"]
mod config_wiping_tests;

pub(super) fn observe_original_parse(body: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    serde_observer::parse(body)
}

use std::cell::RefCell;

use super::{parse_config, Exchange, Exchanged, Request, Response, VaultClient};
use busbar_contract::secret::SecretErrorKind;
use zeroize::Zeroizing;

const TOKEN: &[u8] = b"s.CANARY-TOKEN-7f3a";
const VALUE: &str = "CANARY-VALUE-91c2";

#[derive(Clone, Copy)]
pub(super) struct Watching;
fn observe_json(what: &'static str, bytes: &[u8]) {
    probe::watch(what, bytes);
}

trait WatchedClient {
    fn resolve_with(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        exchange: &dyn Exchange,
        _: Watching,
    ) -> Option<busbar_contract::secret::SecretResult<Vec<u8>>>;
}
impl WatchedClient for VaultClient {
    fn resolve_with(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        exchange: &dyn Exchange,
        _: Watching,
    ) -> Option<busbar_contract::secret::SecretResult<Vec<u8>>> {
        busbar_contract::abi::sdk::test_support::chip::with_json_observer(observe_json, || {
            self.resolve(settings, exchange)
                .map(|r| r.map(crate::custody_support::material))
        })
    }
}

fn parse_config_observed(bytes: &[u8]) -> Result<crate::VaultConfig, String> {
    let config =
        busbar_contract::abi::sdk::test_support::chip::with_json_observer(observe_json, || {
            crate::parse_config(bytes)
        })?;
    watch_config(&config);
    Ok(config)
}

pub(super) fn watch_config(config: &super::VaultConfig) {
    probe::watch("config address", config.addr.as_bytes());
    fn watch(value: &serde_json::Value) {
        match value {
            serde_json::Value::String(text) => probe::watch("config token", text.as_bytes()),
            serde_json::Value::Array(items) => items.iter().for_each(watch),
            serde_json::Value::Object(items) => {
                for (name, value) in items {
                    probe::watch("config token key", name.as_bytes());
                    watch(value);
                }
            }
            _ => {}
        }
    }
    watch(&config._token);
    if let Some(pem) = &config.ca_cert_pem {
        probe::watch("config CA", pem.as_bytes());
    }
}

struct Moves {
    status: u16,
    body: RefCell<Option<Vec<u8>>>,
}

impl Exchange for Moves {
    fn exchange(&self, request: &Request) -> Exchanged {
        let token = &request.fields[0].1;
        assert_eq!(crate::custody_support::token(token), TOKEN);
        busbar_contract::abi::sdk::test_support::chip::observe_credential(token, |bytes| {
            probe::watch("token", bytes)
        });
        let body = self.body.borrow_mut().take().expect("one exchange");
        probe::watch("response body", &body);
        Exchanged::Done(Ok(Response {
            status: self.status,
            body_len: body.len(),
            body: busbar_contract::abi::sdk::cred::Held::new(body),
        }))
    }
}

fn client() -> VaultClient {
    let cfg = parse_config(br#"{"addr":"http://v:8200","token":{"env":"T"}}"#).unwrap();
    VaultClient::new(&cfg, TOKEN)
}

fn settings(field: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({ "path": "kv/data/x", "field": field })
        .as_object()
        .unwrap()
        .clone()
}

fn body() -> Vec<u8> {
    serde_json::json!({
        "data": { "data": { "k": VALUE, "other": { "array": [VALUE, { "nested": VALUE }] } } }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn a_resolve_wipes_token_body_siblings_and_the_returned_material() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(body())),
    };
    let settings = settings("k");
    let observed = probe::Probe::start();
    let client = client();
    let material = Zeroizing::new(
        client
            .resolve_with(&settings, &exchange, Watching)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(material.as_slice(), VALUE.as_bytes());
    drop(material);
    drop(client);
    let report = observed.finish();
    assert_eq!(
        report.allocations_for("parsed value"),
        1,
        "only the selected string is decoded; siblings are validated without copies"
    );
    report.assert_wiped(&["token", "response body", "parsed value"]);
}

#[test]
fn a_non_string_field_wipes_its_tree_and_its_rendered_material() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(body())),
    };
    let settings = settings("other");
    let observed = probe::Probe::start();
    let client = client();
    let material = Zeroizing::new(
        client
            .resolve_with(&settings, &exchange, Watching)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        material.capacity(),
        material.len(),
        "render() pre-sizes its buffer: no growth, so no partial unwiped copy is freed"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&material).unwrap(),
        serde_json::json!({ "array": [VALUE, { "nested": VALUE }] })
    );
    drop(material);
    drop(client);
    observed
        .finish()
        .assert_wiped(&["token", "response body", "parsed value"]);
}

/// A numeric field is returned as rendered material; the key text of an object field and the number
/// itself are copies in the freed tree and must be wiped like the strings.
#[test]
fn an_object_field_wipes_its_decoded_keys_and_rendered_number() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(
            br#"{"data":{"data":{"cred":{"svc-user-key-5e1d":918273645012}}}}"#.to_vec(),
        )),
    };
    let settings = settings("cred");
    let observed = probe::Probe::start();
    let client = client();
    let material = Zeroizing::new(
        client
            .resolve_with(&settings, &exchange, Watching)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        material.as_slice(),
        br#"{"svc-user-key-5e1d":918273645012}"#
    );
    drop(material);
    drop(client);
    observed
        .finish()
        .assert_wiped(&["token", "response body", "parsed key"]);
}

#[test]
fn a_missing_field_wipes_the_parsed_tree_before_refusing() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(body())),
    };
    let settings = settings("absent");
    let observed = probe::Probe::start();
    let client = client();
    let error = client
        .resolve_with(&settings, &exchange, Watching)
        .unwrap()
        .err()
        .unwrap();
    assert_eq!(error.kind, SecretErrorKind::NotFound);
    assert!(!error.message.contains(VALUE));
    drop(error);
    drop(client);
    observed
        .finish()
        .assert_wiped(&["token", "response body", "parsed key"]);
}

#[test]
fn a_failed_parse_wipes_the_owned_response_body() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(format!("{{\"data\":\"{VALUE}\",broken").into_bytes())),
    };
    let settings = settings("k");
    let observed = probe::Probe::start();
    let client = client();
    let error = client
        .resolve_with(&settings, &exchange, Watching)
        .unwrap()
        .err()
        .unwrap();
    assert_eq!(error.kind, SecretErrorKind::Internal);
    assert!(!error.message.contains(VALUE));
    drop(error);
    drop(client);
    observed.finish().assert_wiped(&["token", "response body"]);
}

#[test]
fn a_refusal_before_parsing_still_wipes_the_response_body() {
    let exchange = Moves {
        status: 403,
        body: RefCell::new(Some(body())),
    };
    let settings = settings("k");
    let observed = probe::Probe::start();
    let client = client();
    let error = client
        .resolve_with(&settings, &exchange, Watching)
        .unwrap()
        .err()
        .unwrap();
    assert_eq!(error.kind, SecretErrorKind::Denied);
    assert!(!error.message.contains(VALUE));
    drop(error);
    drop(client);
    observed.finish().assert_wiped(&["token", "response body"]);
}

#[test]
fn giving_up_a_pending_resolve_wipes_the_clients_token() {
    struct Pending;
    impl Exchange for Pending {
        fn exchange(&self, request: &Request) -> Exchanged {
            let token = &request.fields[0].1;
            assert_eq!(crate::custody_support::token(token), TOKEN);
            busbar_contract::abi::sdk::test_support::chip::observe_credential(token, |bytes| {
                probe::watch("token", bytes)
            });
            Exchanged::Pending
        }
    }
    let settings = settings("k");
    let observed = probe::Probe::start();
    let client = client();
    assert!(client.resolve(&settings, &Pending).is_none());
    drop(client);
    observed.finish().assert_wiped(&["token"]);
}

#[test]
fn escaped_strings_and_duplicate_subtrees_are_wiped_on_release() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(
            br#"{"data":{"data":{"k":{"lost":"CANARY\u002dVALUE-91c2"},"\u006b":"CANARY\u002dVALUE-91c2","other":["escaped\nvalue","\ud83d\ude80"]}}}"#
                .to_vec(),
        )),
    };
    let settings = settings("k");
    let observed = probe::Probe::start();
    let client = client();
    let material = Zeroizing::new(
        client
            .resolve_with(&settings, &exchange, Watching)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(material.as_slice(), VALUE.as_bytes());
    drop(material);
    drop(client);
    observed
        .finish()
        .assert_wiped(&["token", "response body", "parsed value"]);
}

#[test]
fn malformed_nested_json_wipes_decoded_values_and_partial_escape_output() {
    for body in [
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2","nested":["sibling",]}}}"#.as_slice(),
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2\q"}}}"#,
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2\ud800"}}}"#,
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2"},"dangling""value"}}"#,
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2"}}} trailing"#,
    ] {
        let exchange = Moves {
            status: 200,
            body: RefCell::new(Some(body.to_vec())),
        };
        let settings = settings("k");
        let observed = probe::Probe::start();
        let client = client();
        let error = client
            .resolve_with(&settings, &exchange, Watching)
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(error.kind, SecretErrorKind::Internal);
        assert!(error.message.contains("is not valid JSON"));
        assert!(!error.message.contains(VALUE));
        assert!(!error.message.contains("CANARY"));
        drop(error);
        drop(client);
        observed.finish().assert_wiped(&["token", "response body"]);
    }
}

#[test]
fn an_escaped_value_before_a_later_syntax_error_is_wiped() {
    let exchange = Moves {
        status: 200,
        body: RefCell::new(Some(
            br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2","nested":[null,]}}}"#.to_vec(),
        )),
    };
    let settings = settings("k");
    let observed = probe::Probe::start();
    let client = client();
    let error = client
        .resolve_with(&settings, &exchange, Watching)
        .unwrap()
        .err()
        .unwrap();
    assert_eq!(error.kind, SecretErrorKind::Internal);
    assert!(!error.message.contains("CANARY"));
    drop(error);
    drop(client);
    observed.finish().assert_decoded_wiped();
}

#[test]
fn observation_preserves_the_original_serde_value_parser() {
    for body in [
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2"}}}"#.as_slice(),
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2","nested":[null,]}}}"#,
        br#"{"\u006b":[true,false,null,-1,18446744073709551615,1.25e30],"k":"last"}"#,
        br#"{"k":"CANARY\q"}"#,
    ] {
        assert_eq!(
            observe_original_parse(body).map_err(|error| error.to_string()),
            serde_json::from_slice::<serde_json::Value>(body).map_err(|error| error.to_string()),
        );
    }
}

#[test]
fn observation_detects_the_original_serde_decoders_real_escaped_scratch() {
    let observed = probe::Probe::start();
    let result = observe_original_parse(
        br#"{"data":{"data":{"k":"CANARY\u002dVALUE-91c2","nested":[null,]}}}"#,
    );
    assert!(result.is_err());
    drop(result);
    observed.finish().assert_unwiped("parser scratch");
}

#[test]
fn partial_render_and_its_growth_allocations_are_observed_and_wiped() {
    // Numeric elements exercise the renderer without any decoded string value buffers.
    // The final comma forces failure after the buffer has grown several times.
    let body = format!(
        "{{\"data\":{{\"data\":{{\"k\":[{}]}}}}}}",
        "918273645,".repeat(64)
    );
    let observed = probe::Probe::start();
    let result =
        busbar_contract::abi::sdk::test_support::chip::with_json_observer(observe_json, || {
            busbar_contract::abi::sdk::cred::select_json(
                busbar_contract::abi::sdk::cred::Held::new(body.as_bytes().to_vec()),
                &["data", "data", "k"],
            )
        });
    assert!(result.is_err());
    drop(result);
    let report = observed.finish();
    assert!(
        report.allocations_for("parsed value") > 1,
        "growth and the final partial render must both be observed"
    );
    report.assert_wiped(&["parse view", "parsed key", "parsed value"]);
}
