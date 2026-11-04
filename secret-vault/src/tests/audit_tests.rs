// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::secret::SecretErrorKind;
use std::cell::Cell;

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
                body: body.as_bytes().to_vec(),
                body_len: body.len(),
            }),
        )
        .unwrap();
        assert_eq!(result, expected.as_bytes());
    }
}

#[test]
fn unrelated_subtrees_are_validated_without_decoding_allocations() {
    #[derive(Clone, Copy)]
    struct Count<'a>(&'a Cell<usize>);
    impl Custody for Count<'_> {
        fn held(self, what: response_json::Held, _: &[u8]) {
            if what != response_json::Held::View {
                self.0.set(self.0.get() + 1);
            }
        }
    }
    let body = format!(
        "{{\"ignored\":[{}],\"data\":{{\"data\":{{\"k\":\"secret\"}}}}}}",
        vec![r#"{"":"unused"}"#; 10_000].join(",")
    );
    let count = Cell::new(0);
    let selected = response_json::select(body.as_bytes(), "k", Count(&count)).unwrap();
    assert!(matches!(selected, Selected::Text(ref text) if text.as_str() == "secret"));
    assert_eq!(
        count.get(),
        5,
        "four path keys and one selected string, independent of sibling count"
    );
    let malformed = body.replace("unused", r"bad\q");
    assert!(response_json::select(malformed.as_bytes(), "k", Unwatched).is_err());
}

#[test]
fn config_refusals_keep_serde_wording_and_document_order() {
    #[allow(dead_code)]
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VaultConfig {
        addr: String,
        token: serde_json::Value,
        ca_cert_pem: Option<String>,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    }
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
        let expected = serde_json::from_str::<VaultConfig>(body)
            .unwrap_err()
            .to_string();
        assert_eq!(
            parse_config(body.as_bytes()).unwrap_err(),
            format!("invalid hashicorp-vault plugin config: {expected}"),
            "{body}"
        );
    }
}

#[test]
fn malformed_string_errors_keep_serde_positions() {
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
        let expected = serde_json::from_slice::<serde_json::Value>(body)
            .unwrap_err()
            .to_string();
        assert_eq!(
            response_json::select(body, "k", Unwatched).err().unwrap(),
            expected
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
        let error = judge(
            path,
            "k",
            &request.url,
            Err(ConnFailure::Failed(String::new())),
        )
        .unwrap_err();
        assert!(
            error
                .message
                .ends_with(&format!("error sending request for url ({parsed})")),
            "{}",
            error.message
        );
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
                .unwrap_err()
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
fn transport_failure_url_normalizes_authority_like_reqwest() {
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
        let expected = reqwest::Url::parse(&request.url).unwrap();
        let error = judge(
            "a/../b",
            "k",
            &request.url,
            Err(ConnFailure::Failed(String::new())),
        )
        .unwrap_err();
        assert!(
            error
                .message
                .ends_with(&format!("error sending request for url ({expected})")),
            "{}",
            error.message
        );
    }
}
