// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::secret::SecretErrorKind;

#[test]
fn selected_values_keep_value_parser_semantics() {
    for body in [
        r#"{"data":{"data":{"k":{"z":1,"a":[true,null,"x"],"z":2}}}}"#,
        r#"{"data":{"data":{"k":"first","\u006b":"last"}}}"#,
        r#"{"data":{"data":{"k":"first"}},"data":{"data":{"k":"last"}}}"#,
        r#"{"data":{"data":{"k":false}}}"#,
        r#"{"data":{"data":{"k":0}}}"#,
        r#"{"data":{"data":{"k":[]}}}"#,
    ] {
        let tree: serde_json::Value = serde_json::from_str(body).unwrap();
        let value = &tree["data"]["data"]["k"];
        let expected = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        let result = judge(
            "p",
            "k",
            "http://v/v1/p",
            Ok(Response {
                status: 200,
                body: busbar_contract::abi::sdk::cred::Held::new(body.as_bytes().to_vec()),
                body_len: body.len(),
            }),
        )
        .unwrap();
        assert_eq!(result, expected.as_bytes());
    }
}

#[test]
fn config_refusals_keep_schema_policy_without_quoting_values() {
    for body in [
        r#"{"addr":true,"token":"t"}"#,
        r#"{"addr":"http://v","token":"t","ca_cert_pem":17}"#,
        r#"{"addr":"http://v","token":"t","timeout_secs":-1}"#,
        r#"{"addr":"http://v","token":"t","timeout_secs":"wrong"}"#,
        r#"{"unknown":1,"unknown":2}"#,
        r#"{"addr":"http://v","addr":"http://w","token":"t"}"#,
        r#"{"token":"t"}"#,
        r#"true"#,
        r#""wrong root""#,
    ] {
        let error = parse_config(body.as_bytes()).err().unwrap();
        assert!(
            error.starts_with("invalid hashicorp-vault plugin config:"),
            "{error}"
        );
        assert!(
            !error.contains("wrong root") && !error.contains("http://w"),
            "{error}"
        );
        assert!(!error.contains("vault-byte="), "{error}");
    }
}

#[test]
fn malformed_string_errors_report_safe_current_parser_context() {
    for body in [
        br#"{"data":{"data":{"k":"bad\q"}}}"#.as_slice(),
        br#"{"data":{"data":{"k":"bad\u12"}}}"#,
        br#"{"data":{"data":{"k":"bad\u1"}}}"#,
        br#"{"data":{"data":{"k":"bad\u"}}}"#,
        b"{\"data\":{\"data\":{\"k\":\"bad\xff\\ud800\"}}}",
        b"{\"data\":{\"data\":{\"k\":\"bad\xff\\n\"}}}",
        br#"{"data":{"data":{"k":"bad\ud800"}}}"#,
        br#"{"data":{"data":{"k":"bad\ud800x"#,
        br#"{"data":{"data":{"k":"bad\udc00"#,
        br#"{"data":{"data":{"k":"bad\ud800"#,
        br#"{"data":{"data":{"k":"bad\uD800x"}}}"#,
        br#"{"data":{"data":{"k":"bad\uD800\n"}}}"#,
        br#"{"data":{"data":{"k":"bad\uDC00suffix"}}}"#,
        br#"{"data":{"data":{"k":"bad\uD800\u0041suffix"}}}"#,
        b"{\"data\":{\"data\":{\"k\":\"bad\x01text\"}}}",
        br#"{"unselected":"bad\q","data":{"data":{"k":"secret"}}}"#,
    ] {
        let error = cred::select_json(Held::new(body.to_vec()), &["data", "data", "k"])
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("line ") && error.contains(" column "),
            "{error}"
        );
        assert!(!error.contains("vault-byte="), "{error}");
        assert!(
            !error.contains("secret") && !error.contains("bad"),
            "{error}"
        );
    }
}

#[test]
fn request_targets_match_reqwest_url_parsing() {
    let config = parse_config(br#"{"addr":"https://v:8200/base","token":"t"}"#).unwrap();
    let client = VaultClient::new(&config, b"token");
    for path in [
        "kv/data/a#b",
        "kv/data/a\tb\nc\r",
        "kv/data/a ",
        "a/../b",
        "a\\b",
        "a?x=' #fragment",
        "café",
        "a/%2e%2e/b",
    ] {
        let request = client.request(path).unwrap();
        let parsed = reqwest::Url::parse(&request.url).unwrap();
        let expected = match parsed.query() {
            Some(query) => format!("{}?{query}", parsed.path()),
            None => parsed.path().to_owned(),
        };
        assert_eq!(request.target, expected, "{path:?}");
    }
}

#[test]
fn transport_failures_preserve_retryability_classes() {
    for (failure, kind) in [
        (
            ConnFailure::CredentialUnavailable,
            SecretErrorKind::Unavailable,
        ),
        (ConnFailure::NoTicket, SecretErrorKind::Internal),
        (ConnFailure::Fault, SecretErrorKind::Internal),
    ] {
        assert_eq!(
            judge("p", "k", "http://v/v1/p", Err(failure))
                .err()
                .unwrap()
                .kind,
            kind
        );
    }
}

#[test]
fn requests_share_the_wiped_ca_allocation() {
    let mut cfg = parse_config(br#"{"addr":"http://v","token":"t"}"#).unwrap();
    cfg.ca_cert_pem = Some("certificate".to_owned());
    let client = VaultClient::new(&cfg, b"token");
    let first = client.request("a").unwrap();
    let second = client.request("b").unwrap();
    assert!(Arc::ptr_eq(
        first.trust_pem.as_ref().unwrap(),
        second.trust_pem.as_ref().unwrap()
    ));
}

#[test]
fn transport_failures_report_target_and_connector_cause() {
    for addr in [
        "http://VAULT:80",
        "https://VAULT:443",
        "http://[0:0:0:0:0:0:0:1]:80",
    ] {
        let body = serde_json::json!({"addr": addr, "token": "t"}).to_string();
        let config = parse_config(body.as_bytes()).unwrap();
        let request = VaultClient::new(&config, b"token")
            .request("a/../b")
            .unwrap();
        let error = judge(
            "a/../b",
            "k",
            &request.url,
            Err(ConnFailure::Failed("connection refused".into())),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind, SecretErrorKind::Unavailable);
        assert!(error.message.contains(&request.url), "{}", error.message);
        assert!(
            error.message.contains("connection refused"),
            "{}",
            error.message
        );
        assert!(!error.message.contains("token"), "{}", error.message);
    }
}

use crate::custody_support::judge;
