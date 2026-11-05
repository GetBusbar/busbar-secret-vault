// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests for the sans-IO Vault KV v2 client: reference-parsing (both
//! forms), config validation, response classification, and secret custody.

use super::*;
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::secret::{error_kind, settings_of};
use busbar_contract::secret::SecretErrorKind;
use serde_json::json;

fn settings(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn hash_suffix_addressing_matches_the_published_doc_convention() {
    let s = settings(json!({ "path": "kv/data/openai#api_key" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/openai");
    assert_eq!(field, "api_key");
}

#[test]
fn explicit_field_key_is_accepted() {
    let s = settings(json!({ "path": "kv/data/openai", "field": "api_key" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/openai");
    assert_eq!(field, "api_key");
}

#[test]
fn explicit_field_wins_over_a_hash_in_path() {
    let s = settings(json!({ "path": "kv/data/weird#name", "field": "real_field" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/weird#name");
    assert_eq!(field, "real_field");
}

#[test]
fn a_non_string_field_is_refused_not_ignored() {
    for s in [
        json!({ "path": "kv/data/x#old", "field": 123 }),
        json!({ "path": "kv/data/x", "field": 7 }),
        json!({ "path": "kv/data/x", "field": null }),
    ] {
        let err = parse_reference(&settings(s)).unwrap_err();
        assert_eq!(err.kind, SecretErrorKind::Invalid);
        assert_eq!(
            err.message,
            "`field` in secret reference settings must be a string"
        );
    }
}

#[test]
fn missing_path_is_rejected() {
    let s = settings(json!({ "field": "api_key" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Invalid);
    assert!(err.message.contains("path"), "{}", err.message);
}

#[test]
fn path_with_no_field_and_no_hash_is_rejected() {
    let s = settings(json!({ "path": "kv/data/openai" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Invalid);
    assert!(err.message.contains("field to extract"), "{}", err.message);
}

#[test]
fn empty_field_after_hash_is_rejected() {
    let s = settings(json!({ "path": "kv/data/openai#" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Invalid);
    assert!(err.message.contains("field to extract"), "{}", err.message);
}

#[test]
fn empty_explicit_field_is_rejected() {
    let s = settings(json!({ "path": "kv/data/openai", "field": "" }));
    let err = parse_reference(&s).unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Invalid);
    assert!(err.message.contains("must not be empty"), "{}", err.message);
}

/// End-to-end against a REAL Vault dev-mode server, gated on `BUSBAR_TEST_VAULT_ADDR` +
/// `BUSBAR_TEST_VAULT_TOKEN` — mirrors `store-postgres`'s `BUSBAR_TEST_POSTGRES_URL` pattern
/// exactly, including the hard-fail-under-CI guard: skips cleanly when unset LOCALLY, but a
/// missing var under `CI` is a hard failure, not a silent skip, so this — the only live coverage
/// of the real Vault HTTP client — cannot quietly vanish.
///
/// Start a real Vault first:
/// ```sh
/// docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
/// BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test -p busbar-secret-vault
/// ```
///
/// Vault dev mode auto-mounts a `kv-v2` engine at `secret/`, so the test seeds
/// `secret/data/busbar-test` directly via a raw HTTP POST (a read-only client can't test itself
/// without something to read) and reads it back through [`VaultClient`] over [`ReqwestExchange`] (the test's stand-in for the host's framed exchange), asserting BOTH
/// field-addressing forms and the fail-closed 404 path.
#[test]
fn roundtrip_against_live_vault() {
    let (addr, token) = match (
        std::env::var("BUSBAR_TEST_VAULT_ADDR"),
        std::env::var("BUSBAR_TEST_VAULT_TOKEN"),
    ) {
        (Ok(addr), Ok(token)) => (addr, token),
        _ if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_VAULT_ADDR / BUSBAR_TEST_VAULT_TOKEN are unset under CI: a Vault \
                 dev-mode service container must provision them (see .github/workflows/ci.yml). \
                 Refusing to silently skip the only live-Vault coverage in CI."
            );
        }
        _ => {
            eprintln!(
                "skip: set BUSBAR_TEST_VAULT_ADDR + BUSBAR_TEST_VAULT_TOKEN to run the live \
                 Vault test (docker run --rm -p 8200:8200 --cap-add=IPC_LOCK \
                 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault)"
            );
            return;
        }
    };

    let seed = reqwest::blocking::Client::new();
    let put_body =
        json!({ "data": { "api_key": "sk-live-abc123", "org_id": "org-xyz" } }).to_string();
    let put_resp = seed
        .post(format!("{addr}/v1/secret/data/busbar-test"))
        .header("X-Vault-Token", &token)
        .header("Content-Type", "application/json")
        .body(put_body)
        .send()
        .expect("seed PUT to Vault failed (is the dev server running and reachable?)");
    assert!(
        put_resp.status().is_success(),
        "seeding the test secret failed: HTTP {}",
        put_resp.status()
    );

    let module = VaultClient::new(&cfg(&addr), token.as_bytes());
    let ex = ReqwestExchange;

    let hash_settings = settings(json!({ "path": "secret/data/busbar-test#api_key" }));
    let got = module
        .resolve(&hash_settings, &ex)
        .unwrap()
        .expect("resolve api_key");
    assert_eq!(got, b"sk-live-abc123");

    let explicit_settings =
        settings(json!({ "path": "secret/data/busbar-test", "field": "org_id" }));
    let got = module
        .resolve(&explicit_settings, &ex)
        .unwrap()
        .expect("resolve org_id");
    assert_eq!(got, b"org-xyz");

    let missing = settings(json!({ "path": "secret/data/no-such-secret#x" }));
    let err = module.resolve(&missing, &ex).unwrap().unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::NotFound);
    assert!(
        err.message.contains("404"),
        "expected a 404 error, got: {}",
        err.message
    );

    let bad_field = settings(json!({ "path": "secret/data/busbar-test#no_such_field" }));
    let err = module.resolve(&bad_field, &ex).unwrap().unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::NotFound);
    assert!(
        err.message.contains("no_such_field"),
        "got: {}",
        err.message
    );

    let bad = VaultClient::new(&cfg(&addr), b"not-a-real-token");
    let err = bad.resolve(&hash_settings, &ex).unwrap().unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Denied);
    assert!(
        err.message.contains("403"),
        "expected a 403 error, got: {}",
        err.message
    );
}

/// The token the tests' client holds; no error text may carry it.
const TOKEN: &[u8] = b"s.never-in-a-message";

fn cfg(addr: &str) -> VaultConfig {
    VaultConfig {
        addr: addr.to_string(),
        token: json!({ "env": "VAULT_TOKEN" }),
        ca_cert_pem: None,
        timeout_secs: 10,
    }
}

/// The test's stand-in for the host's framed one-shot exchange: a real HTTP client, as 1.5.5's
/// implementation used, driven through the same request target.
struct ReqwestExchange;

impl Exchange for ReqwestExchange {
    fn exchange(&self, r: &Request) -> Exchanged {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(r.timeout_ms))
            .build()
            .expect("client");
        let parsed = reqwest::Url::parse(&r.url).expect("request URL");
        let url = format!("{}{}", parsed.origin().ascii_serialization(), r.target);
        let mut req = client.get(url);
        for (n, v) in &r.fields {
            req = req.header(*n, v.as_slice());
        }
        Exchanged::Done(match req.send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = match resp.bytes() {
                    Ok(body) => body.to_vec(),
                    Err(error) => {
                        return Exchanged::Done(Err(ConnFailure::Failed(error.to_string())))
                    }
                };
                let body_len = body.len();
                let body = body[..body_len.min(r.body_cap)].to_vec();
                Ok(Response {
                    status,
                    body,
                    body_len,
                })
            }
            Err(e) => Err(ConnFailure::Failed(e.to_string())),
        })
    }
}

/// An exchange answering one canned response (or transport failure), recording the request.
struct Canned {
    answer: Result<Response, ConnFailure>,
    seen: std::sync::Mutex<Vec<String>>,
}

impl Canned {
    fn status(status: u16, body: &str) -> Self {
        Self::of(Ok(Response {
            status,
            body: body.as_bytes().to_vec(),
            body_len: body.len(),
        }))
    }

    fn of(answer: Result<Response, ConnFailure>) -> Self {
        Self {
            answer,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Exchange for Canned {
    fn exchange(&self, r: &Request) -> Exchanged {
        self.seen
            .lock()
            .unwrap()
            .push(format!("{} {}", r.method, r.url));
        Exchanged::Done(self.answer.clone())
    }
}

const ADDR: &str = "http://vault.internal:8200/";
const URL: &str = "http://vault.internal:8200/v1/kv/data/openai";

fn run(ex: &dyn Exchange, reference: serde_json::Value) -> SecretResult<Vec<u8>> {
    let r = VaultClient::new(&cfg(ADDR), TOKEN)
        .resolve(&settings(reference), ex)
        .expect("a canned exchange never pends");
    if let Err(e) = &r {
        let token = String::from_utf8_lossy(TOKEN);
        assert!(
            !e.message.contains(token.as_ref()),
            "the token leaked: {}",
            e.message
        );
    }
    r
}

fn kv2(data: serde_json::Value) -> String {
    json!({ "data": { "data": data, "metadata": { "version": 1 } } }).to_string()
}

#[test]
fn the_request_is_1_5_5s_get_with_the_token_header() {
    let c = VaultClient::new(&cfg(ADDR), TOKEN);
    let r = c.request("/kv/data/openai").expect("a valid URL");
    assert_eq!(r.method, "GET");
    assert_eq!(
        r.url, URL,
        "trailing slash trimmed once, leading slash of the path trimmed"
    );
    let fields: Vec<(&str, &[u8])> = r.fields.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    assert_eq!(fields, vec![("X-Vault-Token", TOKEN)]);
    assert_eq!(r.timeout_ms, 10_000);
    assert_eq!(r.body_cap, MAX_VAULT_RESPONSE_BYTES + 1);
    assert!(r.trust_pem.is_none());
    let shown = format!("{r:?} {c:?}");
    assert!(
        !shown.contains("never-in-a-message"),
        "Debug prints the token: {shown}"
    );
    // `Vec<u8>`'s derived `Debug` prints the bytes as numbers: look for those too.
    let as_bytes = format!("{TOKEN:?}");
    let as_bytes = &as_bytes[1..as_bytes.len() - 1];
    for text in [
        format!("{r:?}"),
        format!("{r:#?}"),
        format!("{c:?}"),
        format!("{c:#?}"),
    ] {
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !flat.contains(as_bytes),
            "Debug carried the token's bytes: {text}"
        );
    }
}

#[test]
fn a_field_is_read_as_its_string_bytes_or_its_json_text() {
    let ex = Canned::status(
        200,
        &kv2(json!({ "api_key": "sk-1", "n": 7, "o": { "a": true } })),
    );
    assert_eq!(
        run(&ex, json!({ "path": "kv/data/openai#api_key" })).unwrap(),
        b"sk-1"
    );
    assert_eq!(
        run(&ex, json!({ "path": "kv/data/openai", "field": "n" })).unwrap(),
        b"7"
    );
    assert_eq!(
        run(&ex, json!({ "path": "kv/data/openai#o" })).unwrap(),
        br#"{"a":true}"#
    );
    assert_eq!(ex.seen.lock().unwrap()[0], format!("GET {URL}"));
}

#[test]
fn a_malformed_reference_is_refused_before_any_exchange() {
    let ex = Canned::status(200, "{}");
    let e = run(&ex, json!({ "path": "kv/data/openai" })).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert!(ex.seen.lock().unwrap().is_empty());
}

/// Response classes retain useful, non-disclosing diagnostics.
#[test]
fn response_classes_report_kind_and_safe_context() {
    let p = "\"kv/data/openai\"";
    let cases: Vec<(Canned, SecretErrorKind, String)> = vec![
        (
            Canned::of(Err(ConnFailure::Failed("connection refused".into()))),
            SecretErrorKind::Unavailable,
            format!(
                "request to Vault ({URL}) failed: \
                 connection refused"
            ),
        ),
        (
            Canned::of(Err(ConnFailure::Failed("  \n".into()))),
            SecretErrorKind::Unavailable,
            format!("request to Vault ({URL}) failed"),
        ),
        (
            Canned::of(Err(ConnFailure::Refused("egress class refused".into()))),
            SecretErrorKind::Denied,
            format!(
                "request to Vault ({URL}) failed: \
                 egress class refused"
            ),
        ),
        (
            Canned::of(Err(ConnFailure::Unarmed)),
            SecretErrorKind::Internal,
            format!(
                "request to Vault ({URL}) failed: \
                 the instance was handed no connector"
            ),
        ),
        (
            Canned::status(404, "{\"errors\":[]}"),
            SecretErrorKind::NotFound,
            format!("Vault has no secret at path {p} (404 from {URL})"),
        ),
        (
            Canned::status(403, "{\"errors\":[\"permission denied\"]}"),
            SecretErrorKind::Denied,
            format!(
                "Vault denied reading path {p} (403 from {URL}): check the token is valid and \
                 its policy grants read on this path"
            ),
        ),
        (
            Canned::status(503, "sealed"),
            SecretErrorKind::Unavailable,
            format!("Vault server error reading path {p}: HTTP 503 Service Unavailable from {URL}"),
        ),
        (
            Canned::status(500, ""),
            SecretErrorKind::Unavailable,
            format!(
                "Vault server error reading path {p}: HTTP 500 Internal Server Error from {URL}"
            ),
        ),
        (
            Canned::status(400, "bad request body"),
            SecretErrorKind::Internal,
            format!("Vault returned HTTP 400 Bad Request reading path {p} ({URL})"),
        ),
        (
            Canned::status(200, "not json"),
            SecretErrorKind::Internal,
            format!(
                "Vault response for path {p} is not valid JSON: expected ident at line 1 column 2"
            ),
        ),
        (
            Canned::status(200, "{\"data\":{\"api_key\":\"v1-shape\"}}"),
            SecretErrorKind::Invalid,
            format!(
                "Vault response for path {p} has no `data.data` object (not a KV v2 read? check \
                 the path includes the `data/` segment, e.g. \"mount/data/name\")"
            ),
        ),
        (
            Canned::status(200, &kv2(json!({ "b": "x", "a": "y" }))),
            SecretErrorKind::NotFound,
            format!("Vault secret at path {p} has no field \"api_key\""),
        ),
    ];
    for (ex, kind, text) in cases {
        let e = run(&ex, json!({ "path": "kv/data/openai#api_key" })).unwrap_err();
        assert_eq!((e.kind, e.message.as_str()), (kind, text.as_str()));
    }
}

#[test]
fn no_text_of_the_reply_reaches_a_refusal() {
    for status in [400, 418] {
        let e = run(
            &Canned::status(status, "REPLY-CANARY sk-live-123"),
            json!({ "path": "kv/data/openai#k" }),
        )
        .unwrap_err();
        assert_eq!(e.kind, SecretErrorKind::Internal);
        assert!(!e.message.contains("REPLY-CANARY"), "{}", e.message);
        assert!(!e.message.contains("sk-live"), "{}", e.message);
    }
    let e = run(
        &Canned::status(200, &kv2(json!({ "FIELD-CANARY": "x" }))),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::NotFound);
    assert!(!e.message.contains("FIELD-CANARY"), "{}", e.message);
}

/// A redirect is not followed (the host's exchange follows none): the refusal says so and what to
/// change in the configured address.
#[test]
fn a_redirect_is_refused_saying_it_is_not_followed() {
    let e = run(
        &Canned::status(307, "<a href=\"https://active:8200/\">"),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Internal);
    assert!(
        e.message.ends_with(
            "a redirect is not followed; set `addr` to the address Vault redirects to (e.g. the \
             active node)"
        ),
        "{}",
        e.message
    );
    assert!(!e.message.contains("active:8200"), "{}", e.message);
}

/// An EMPTY field is refused INVALID, as every secret source refuses empty material (fail-closed);
/// no empty material is returned.
#[test]
fn an_empty_field_is_refused_never_resolved_empty() {
    let e = run(
        &Canned::status(200, &kv2(json!({ "k": "" }))),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert_eq!(
        e.message,
        "Vault secret at path \"kv/data/openai\" field \"k\" is EMPTY; a secret must be \
         non-empty (fail-closed)"
    );
}

/// A reference names `path` (and `field`) and nothing else, and a blank `path` names nothing: both
/// are refused before an exchange.
#[test]
fn a_blank_path_or_another_setting_is_refused_before_any_request() {
    let blank = parse_reference(&settings(json!({ "path": "  ", "field": "k" }))).unwrap_err();
    assert_eq!(blank.kind, SecretErrorKind::Invalid);
    assert_eq!(
        blank.message,
        "`path` in secret reference settings must not be blank"
    );
    let other =
        parse_reference(&settings(json!({ "path": "kv/data/x#k", "fields": "k" }))).unwrap_err();
    assert_eq!(other.kind, SecretErrorKind::Invalid);
    assert_eq!(
        other.message,
        "vault secret reference does not take settings.fields; it names only settings.path and \
         settings.field (fail-closed)"
    );
}

/// The open-time settings are judged, not only parsed: an `addr` no request can be built on, a
/// zero timeout, or an invalid CA is refused.
#[test]
fn open_time_settings_that_could_never_serve_are_refused_naming_the_key() {
    let addr = "invalid hashicorp-vault plugin config: `addr` must be an http:// or https:// URL \
                naming the Vault server (e.g. https://vault.internal:8200), with no query or \
                fragment";
    for bad in [
        "",
        "vault.internal:8200",
        "ftp://vault",
        "https://",
        "https://v:8200?token=SECRET-CANARY",
        "https://v:8200#frag",
    ] {
        let cfg = json!({ "addr": bad, "token": { "env": "T" } }).to_string();
        let e = parse_config(cfg.as_bytes()).unwrap_err();
        assert_eq!(e, addr, "{bad}");
    }
    for good in ["http://v", "https://u:p@v:8200/", "https://v:8200/prefix"] {
        let cfg = json!({ "addr": good, "token": { "env": "T" } }).to_string();
        assert!(parse_config(cfg.as_bytes()).is_ok(), "{good}");
    }
    let cfg = json!({ "addr": "https://v", "token": { "env": "T" }, "ca_cert_pem": "not a pem" });
    assert_eq!(
        parse_config(cfg.to_string().as_bytes()).unwrap_err(),
        "invalid hashicorp-vault plugin config: `ca_cert_pem` holds no PEM certificate \
         (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)"
    );
    let cfg = json!({ "addr": "https://v", "token": { "env": "T" }, "timeout_secs": 0 });
    assert_eq!(
        parse_config(cfg.to_string().as_bytes()).unwrap_err(),
        "invalid hashicorp-vault plugin config: `timeout_secs` must be at least 1"
    );
}

/// A BEGIN CERTIFICATE with no END after a complete block is refused, not skipped.
#[test]
fn a_truncated_trailing_certificate_is_refused() {
    // DER SEQUENCE of length 0: 30 00 -> "MAA="
    let good = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
    let pem = format!("{good}-----BEGIN CERTIFICATE-----\nMIIB\n");
    let cfg = json!({ "addr": "https://v", "token": { "env": "T" }, "ca_cert_pem": pem });
    assert_eq!(
        parse_config(cfg.to_string().as_bytes()).unwrap_err(),
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 2 has no \
         -----END CERTIFICATE----- line"
    );
    // A lone cut-off block is the first certificate.
    let cfg = json!({ "addr": "https://v", "token": { "env": "T" },
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n" });
    assert_eq!(
        parse_config(cfg.to_string().as_bytes()).unwrap_err(),
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 has no \
         -----END CERTIFICATE----- line"
    );
}

/// A path that is blank once its `#field` suffix is cut off is blank, not a request to `/v1/%20%20%20`.
#[test]
fn a_blank_path_with_a_field_suffix_is_refused() {
    let e = parse_reference(&settings(json!({ "path": "   #api_key" }))).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert_eq!(
        e.message,
        "`path` in secret reference settings must not be blank"
    );
    // An empty path before `#` is blank too: the field is present, the path is what is missing.
    let e = parse_reference(&settings(json!({ "path": "#api_key" }))).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert_eq!(
        e.message,
        "`path` in secret reference settings must not be blank"
    );
}

/// A Vault rate-limit answer (429) is an outage to wait out.
#[test]
fn a_429_is_unavailable() {
    let e = run(
        &Canned::status(429, "REPLY-CANARY"),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Unavailable);
    assert!(!e.message.contains("REPLY-CANARY"), "{}", e.message);
}

/// `Debug` of a response never prints its body, and of a config never its token reference or the
/// address userinfo.
#[test]
fn debug_prints_no_body_token_or_userinfo() {
    let r = Response {
        status: 200,
        body: b"BODY-CANARY".to_vec(),
        body_len: 11,
    };
    assert!(!format!("{r:?}").contains("BODY-CANARY"));
    let c = parse_config(br#"{"addr":"https://user:PW-CANARY@v","token":{"env":"TOKEN-CANARY"}}"#)
        .unwrap();
    let shown = format!("{c:?}");
    assert!(!shown.contains("PW-CANARY"), "{shown}");
    assert!(!shown.contains("TOKEN-CANARY"), "{shown}");
}

#[test]
fn the_body_cap_refuses_over_and_accepts_at_the_cap() {
    let cap = MAX_VAULT_RESPONSE_BYTES;
    let over = Canned::of(Ok(Response {
        status: 200,
        body: vec![b' '; cap + 1],
        body_len: cap + 1,
    }));
    let e = run(&over, json!({ "path": "kv/data/openai#k" })).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Unavailable);
    assert_eq!(
        e.message,
        format!("Vault response body exceeds the {cap}-byte cap (path \"kv/data/openai\", {URL})")
    );

    let reported = Canned::of(Ok(Response {
        status: 200,
        body: vec![b' '; 10],
        body_len: cap + 7,
    }));
    assert_eq!(
        run(&reported, json!({ "path": "kv/data/openai#k" }))
            .unwrap_err()
            .kind,
        SecretErrorKind::Unavailable
    );

    let mut at = kv2(json!({ "k": "v" })).into_bytes();
    at.resize(cap, b' ');
    let at = Canned::of(Ok(Response {
        status: 200,
        body_len: at.len(),
        body: at,
    }));
    assert_eq!(
        run(&at, json!({ "path": "kv/data/openai#k" })).unwrap(),
        b"v"
    );

    let big404 = Canned::of(Ok(Response {
        status: 404,
        body: vec![],
        body_len: cap * 2,
    }));
    assert_eq!(
        run(&big404, json!({ "path": "kv/data/openai#k" }))
            .unwrap_err()
            .kind,
        SecretErrorKind::NotFound
    );
}

/// 1.5.5 judges the body cap before any other non-2xx: an over-cap 400 or 418 is the cap refusal,
/// while the dedicated 404, 403 and server-error classes retain precedence.
#[test]
fn the_body_cap_is_judged_before_any_other_non_2xx() {
    let cap = MAX_VAULT_RESPONSE_BYTES;
    let over = |status| {
        Canned::of(Ok(Response {
            status,
            body: vec![b'x'; cap + 1],
            body_len: cap + 1,
        }))
    };
    let reference = || json!({ "path": "kv/data/openai#k" });
    for status in [400, 418] {
        let e = run(&over(status), reference()).unwrap_err();
        assert_eq!(e.kind, SecretErrorKind::Unavailable, "{status}");
        assert_eq!(
            e.message,
            format!(
                "Vault response body exceeds the {cap}-byte cap (path \"kv/data/openai\", {URL})"
            ),
            "{status}"
        );
    }
    let e = run(&over(403), reference()).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Denied);
    let e = run(&over(503), reference()).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Unavailable);
    assert!(
        e.message.starts_with("Vault server error reading path"),
        "{}",
        e.message
    );
}

/// An exchange that pends once, then answers: the op answers "not yet", and the re-invoked op
/// collects the stored answer.
struct PendsOnce {
    calls: std::sync::Mutex<u32>,
}

impl Exchange for PendsOnce {
    fn exchange(&self, _: &Request) -> Exchanged {
        let mut n = self.calls.lock().unwrap();
        *n += 1;
        if *n == 1 {
            Exchanged::Pending
        } else {
            Exchanged::Done(Ok(Response {
                status: 200,
                body: kv2(json!({ "k": "late" })).into_bytes(),
                body_len: kv2(json!({ "k": "late" })).len(),
            }))
        }
    }
}

#[test]
fn a_pending_exchange_pends_the_resolve_then_answers_on_resume() {
    let ex = PendsOnce {
        calls: std::sync::Mutex::new(0),
    };
    let c = VaultClient::new(&cfg(ADDR), TOKEN);
    let s = settings(json!({ "path": "kv/data/openai#k" }));
    assert!(c.resolve(&s, &ex).is_none(), "pending");
    assert_eq!(c.resolve(&s, &ex).unwrap().unwrap(), b"late");
}

#[test]
fn config_refusals_name_the_plugin_and_invalid_setting() {
    assert_eq!(
        parse_config(b"  \n").unwrap_err(),
        "hashicorp-vault plugin requires config (addr, token); none provided"
    );
    assert_eq!(
        parse_config(b"").unwrap_err(),
        "hashicorp-vault plugin requires config (addr, token); none provided"
    );
    let e = parse_config(b"{ this is not json").unwrap_err();
    assert!(
        e.contains("invalid hashicorp-vault plugin config") && e.contains("key must be a string"),
        "{e}"
    );
    let e = parse_config(br#"{"addr":"http://v"}"#).unwrap_err();
    assert!(e.contains("missing field `token`"), "{e}");
    let e = parse_config(br#"{"token":"t"}"#).unwrap_err();
    assert!(e.contains("missing field `addr`"), "{e}");
    let e = parse_config(br#"{"addr":"http://v","token":"t","tls":true}"#).unwrap_err();
    assert!(e.contains("unknown field `tls`"), "{e}");
    let c = parse_config(br#"{"addr":"http://v","token":{"env":"T"},"timeout_secs":3}"#).unwrap();
    assert_eq!(
        (c.addr.as_str(), c.timeout_secs, c.ca_cert_pem.as_deref()),
        ("http://v", 3, None)
    );
    assert_eq!(
        parse_config(br#"{"addr":"http://a","token":"t"}"#)
            .unwrap()
            .timeout_secs,
        10
    );
}

#[test]
fn guarded_config_keeps_root_duplicate_refusal_and_nested_value_semantics() {
    let duplicate =
        parse_config(br#"{"addr":"http://first","token":{"env":"T"},"ad\u0064r":"http://second"}"#)
            .unwrap_err();
    assert!(duplicate.contains("duplicate field `addr`"), "{duplicate}");
    let nested =
        parse_config(br#"{"addr":"http://v","token":{"nested":[{"k":"lost","\u006b":"kept"}]}}"#)
            .unwrap();
    assert_eq!(nested.token["nested"][0]["k"], "kept");
}

#[test]
fn the_extra_root_and_timeout_ride_the_request() {
    let mut c = cfg(ADDR);
    c.ca_cert_pem = Some("-----BEGIN CERTIFICATE-----".into());
    c.timeout_secs = 3;
    let r = VaultClient::new(&c, TOKEN)
        .request("kv/data/x")
        .expect("a valid URL");
    assert_eq!(
        r.trust_pem.as_ref().map(|pem| pem.as_str()),
        Some("-----BEGIN CERTIFICATE-----")
    );
    assert_eq!(r.timeout_ms, 3000);
    // `parse_config` accepts any non-zero `timeout_secs`: the millisecond conversion saturates.
    c.timeout_secs = u64::MAX;
    let r = VaultClient::new(&c, TOKEN)
        .request("kv/data/x")
        .expect("a valid URL");
    assert_eq!(r.timeout_ms, u64::MAX);
}

/// The framed target is the path and query, `addr`'s own prefix included, the path carried verbatim
/// after URL normalization and encoding.
#[test]
fn the_framed_target_is_the_path_and_query() {
    let c = VaultClient::new(&cfg("https://vault.internal:8200"), TOKEN);
    assert_eq!(
        c.request("kv/data/x?version=2").unwrap().target,
        "/v1/kv/data/x?version=2"
    );
    let c = VaultClient::new(&cfg("https://v:8200/prefix/"), TOKEN);
    assert_eq!(
        c.request("kv/data/x").unwrap().target,
        "/prefix/v1/kv/data/x"
    );
}

#[test]
fn the_framed_target_percent_encodes_what_a_uri_cannot_hold() {
    let c = VaultClient::new(&cfg("https://v:8200"), TOKEN);
    let target = |p: &str| c.request(p).unwrap().target.clone();
    assert_eq!(target("kv/data/my app"), "/v1/kv/data/my%20app");
    assert_eq!(target("kv/data/caf\u{e9}"), "/v1/kv/data/caf%C3%A9");
    assert_eq!(target("a<b>`"), "/v1/a%3Cb%3E%60");
    assert_eq!(target("kv/data/q?a=1&b=%20"), "/v1/kv/data/q?a=1&b=%20");

    let ex = Canned::status(200, &kv2(json!({ "k": "v" })));
    let got = c
        .resolve(
            &settings(json!({ "path": "kv/data/a#b", "field": "k" })),
            &ex,
        )
        .unwrap();
    assert_eq!(got.unwrap(), b"v");
    assert_eq!(target("kv/data/a#b"), "/v1/kv/data/a");

    assert_eq!(
        c.request("kv/data/a#b").unwrap().url,
        "https://v:8200/v1/kv/data/a#b"
    );
}

#[test]
fn an_addr_that_is_no_url_is_refused_before_any_exchange() {
    let ex = Canned::status(200, &kv2(json!({ "k": "v" })));
    let c = VaultClient::new(&cfg("vault.internal:8200"), TOKEN);
    let e = c
        .resolve(&settings(json!({ "path": "kv/data/x#k" })), &ex)
        .unwrap()
        .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Unavailable);
    let url = "vault.internal:8200/v1/kv/data/x";
    assert!(
        e.message.starts_with(&format!(
            "request to Vault ({url}) failed: the request URL is not a valid URL: "
        )),
        "{}",
        e.message
    );
    assert!(
        ex.seen.lock().unwrap().is_empty(),
        "the exchange is never called"
    );
}

/// An `addr` carrying userinfo never prints it: not in a refusal text, not in `Debug`.
#[test]
fn addr_userinfo_is_never_printed() {
    let reference = settings(json!({ "path": "kv/data/x#k" }));
    for (addr, shown) in [
        (
            "https://svc:s3cret@vault:8200",
            "https://vault:8200/v1/kv/data/x",
        ),
        (
            "https://svc:s3cret@vault:8200/",
            "https://vault:8200/v1/kv/data/x",
        ),
        (
            "https://a@b:s3cret@vault:8200/p",
            "https://vault:8200/p/v1/kv/data/x",
        ),
        ("svc:s3cret@vault:8200", "vault:8200/v1/kv/data/x"),
        (
            "https://vault:8200/p@q",
            "https://vault:8200/p@q/v1/kv/data/x",
        ),
    ] {
        let c = VaultClient::new(&cfg(addr), TOKEN);
        let e = c
            .resolve(&reference, &Canned::status(404, "{}"))
            .unwrap()
            .unwrap_err();
        assert!(e.message.contains(shown), "{}", e.message);
        assert!(!e.message.contains("s3cret"), "{}", e.message);
        assert!(!format!("{c:?}").contains("s3cret"));
    }
}

#[test]
fn every_error_class_has_its_abi_code() {
    use busbar_contract::abi::secret as s;
    assert_eq!(
        error_kind(SecretErrorKind::NotFound),
        s::ERROR_KIND_NOT_FOUND
    );
    assert_eq!(
        error_kind(SecretErrorKind::Unavailable),
        s::ERROR_KIND_UNAVAILABLE
    );
    assert_eq!(error_kind(SecretErrorKind::Denied), s::ERROR_KIND_DENIED);
    assert_eq!(error_kind(SecretErrorKind::Invalid), s::ERROR_KIND_INVALID);
    assert_eq!(
        error_kind(SecretErrorKind::Internal),
        s::ERROR_KIND_INTERNAL
    );
}

#[test]
fn settings_of_reads_an_object_and_refuses_anything_else() {
    assert!(settings_of(b"").unwrap().is_empty());
    assert_eq!(settings_of(br#"{"path":"p"}"#).unwrap()["path"], "p");
    assert_eq!(
        settings_of(b"[1]").unwrap_err().kind,
        SecretErrorKind::Invalid
    );
}

const CANARY: &str = "CANARY3b90e4";

#[test]
fn a_non_2xx_kv_body_never_reaches_the_refusal() {
    for body in [
        format!(r#"{{"data":{{"data":{{"api_key":"{CANARY}","other":"x"}}}}}}"#),
        format!(r#"{{"auth":{{"client_token":"{CANARY}"}}}}"#),
        format!(r#"{{"wrap_info":{{"token":"{CANARY}"}}}}"#),
    ] {
        let e = run(
            &Canned::status(412, &body),
            json!({ "path": "kv/data/openai#k" }),
        )
        .unwrap_err();
        assert!(
            !e.message.contains(CANARY),
            "the refusal carried a secret: {}",
            e.message
        );
        assert!(
            e.message
                .starts_with("Vault returned HTTP 412 Precondition Failed reading path"),
            "{}",
            e.message
        );
    }

    let e = run(
        &Canned::status(400, r#"{"errors":["permission denied"]}"#),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert!(!e.message.contains("permission denied"), "{}", e.message);
    assert!(
        e.message
            .starts_with("Vault returned HTTP 400 Bad Request reading path")
            && e.message.ends_with(')'),
        "{}",
        e.message
    );
}

/// A.3: `Response`'s `Debug` printed its body (the secret material), and `VaultConfig`'s printed
/// its token reference and address userinfo; neither may leak now.
#[test]
fn debug_of_a_response_or_the_config_carries_no_secret() {
    let r = Response {
        status: 200,
        body: format!(r#"{{"data":{{"data":{{"k":"{CANARY}"}}}}}}"#).into_bytes(),
        body_len: 40,
    };
    let c = parse_config(
        format!(r#"{{"addr":"https://svc:{CANARY}@vault:8200","token":"{CANARY}"}}"#).as_bytes(),
    )
    .unwrap();

    let as_bytes = format!("{:?}", CANARY.as_bytes());
    let as_bytes = &as_bytes[1..as_bytes.len() - 1];
    for text in [
        format!("{r:?}"),
        format!("{r:#?}"),
        format!("{c:?}"),
        format!("{c:#?}"),
    ] {
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!text.contains(CANARY), "Debug carried a secret: {text}");
        assert!(
            !flat.contains(as_bytes),
            "Debug carried a secret's bytes: {text}"
        );
    }
    assert!(format!("{c:?}").contains("vault:8200"));
}

/// A real self-signed P-256 certificate (CN=t, valid 100 years), for the `ca_cert_pem` checks.
const REAL_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBTDCB9KADAgECAhRAv5nU49XDV1DnMZdBVXBuEWTXtzAKBggqhkjOPQQDAjAM
MQowCAYDVQQDDAF0MCAXDTI2MTAzMDE5MzMwM1oYDzIxMjYxMDA2MTkzMzAzWjAM
MQowCAYDVQQDDAF0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5y86jWjKK0R/
sCwiSIabwEb+d/HiJLRhIJszyGqjC+ul+AXCv/c3kq3cbDEEl1Pt4EZHP31v8ev6
p8BJC+aaSKMyMDAwHQYDVR0OBBYEFPnMBJuKHy7JwH2V1+noptWAYwvTMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgVyP4/oiNsc6El0BALXr5Evll
YbRfJC7nZIlBGtV3LlwCIAllcUEmL/eYJCDkqXthgpUzPI7QC2pKhPQTsHaBbvvf
-----END CERTIFICATE-----
";

fn config_with_ca(pem: &str) -> Result<VaultConfig, String> {
    let cfg = json!({ "addr": "https://v", "token": { "env": "T" }, "ca_cert_pem": pem });
    parse_config(cfg.to_string().as_bytes())
}

/// 1.5.5 refused a trust anchor `reqwest::Certificate::from_pem` could not decode ("invalid
/// ca_cert_pem"); malformed PEM is refused at open.
#[test]
fn a_ca_cert_pem_that_does_not_decode_is_refused() {
    let junk = "-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----";
    assert_eq!(
        config_with_ca(junk).unwrap_err(),
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 is not valid \
         base64"
    );

    let not_der = "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQh\n-----END CERTIFICATE-----";
    assert_eq!(
        config_with_ca(not_der).unwrap_err(),
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 is not DER (it \
         does not start with a SEQUENCE of the stated length)"
    );

    let truncated = "-----BEGIN CERTIFICATE-----\nMAUBAQ==\n-----END CERTIFICATE-----";
    assert!(config_with_ca(truncated).is_err(), "truncated DER");
    // A SEQUENCE followed by extra bytes: the length must match exactly, short form and long form.
    for (name, b64) in [("short form", "MAD//w=="), ("long form", "MIEBAP8=")] {
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----");
        assert_eq!(
            config_with_ca(&pem).unwrap_err(),
            "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 is not DER \
             (it does not start with a SEQUENCE of the stated length)",
            "trailing bytes after a {name} SEQUENCE"
        );
    }
    // The strict branches of the validator, each refused for its own reason.
    let block =
        |b64: &str| format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----");
    let not_base64 =
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 is \
                      not valid base64";
    let not_der =
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 is not \
                   DER (it does not start with a SEQUENCE of the stated length)";
    for (name, b64) in [
        ("non-zero trailing bits (0x30 0x00 would be DER)", "MAB="),
        ("too much padding", "MA======"),
        ("an alphabet byte in a length-4 body", "MA!A"),
    ] {
        assert_eq!(
            config_with_ca(&block(b64)).unwrap_err(),
            not_base64,
            "{name}"
        );
    }
    // 0x30 0x80: an indefinite length is not DER.
    assert_eq!(
        config_with_ca(&block("MIA=")).unwrap_err(),
        not_der,
        "indefinite length"
    );
    // The real (long-form) certificate with one stray byte after the SEQUENCE.
    let body: String = REAL_CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let mut der = decode_base64(&body).expect("the real certificate decodes");
    der.push(0);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut enc = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                enc.push(char::from(alphabet[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                enc.push('=');
            }
        }
    }
    assert_eq!(
        config_with_ca(&block(&enc)).unwrap_err(),
        not_der,
        "trailing DER byte"
    );
    // A good block followed by a bad one: the bad one is named by its position.
    let second =
        format!("{REAL_CERT_PEM}-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----");
    assert!(config_with_ca(&second)
        .unwrap_err()
        .contains("certificate 2"));
    let empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----";
    assert!(config_with_ca(empty).is_err(), "an empty block");
}

#[test]
fn a_real_certificate_is_accepted_alone_and_in_a_bundle() {
    assert!(config_with_ca(REAL_CERT_PEM).is_ok());
    assert!(config_with_ca(&format!("{REAL_CERT_PEM}{REAL_CERT_PEM}")).is_ok());

    let crlf = format!("subject: t\r\n{}", REAL_CERT_PEM.replace('\n', "\r\n"));
    assert!(config_with_ca(&crlf).is_ok());
}

#[test]
fn an_end_marker_before_the_begin_marker_is_refused() {
    let reversed = "-----END CERTIFICATE-----\nMAA=\n-----BEGIN CERTIFICATE-----";
    assert_eq!(
        config_with_ca(reversed).unwrap_err(),
        "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate 1 has no \
         -----END CERTIFICATE----- line"
    );
}

/// 1.5.5 parsed `{addr}/v1/{path}` with the `url` crate, which removes dot segments and turns `\`
#[test]
fn the_framed_target_normalises_the_path_as_the_url_crate_did() {
    let c = VaultClient::new(&cfg("https://v:8200"), TOKEN);
    let target = |p: &str| c.request(p).unwrap().target;
    assert_eq!(target("kv/data/team/../openai"), "/v1/kv/data/openai");
    assert_eq!(target("kv/./data/x"), "/v1/kv/data/x");
    assert_eq!(target("kv\\data\\x"), "/v1/kv/data/x");
    assert_eq!(target("kv/%2e/data/%2E%2e/x"), "/v1/kv/x");
    assert_eq!(target("kv/data/x/."), "/v1/kv/data/x/");
    assert_eq!(target("kv/data/.."), "/v1/kv/");

    assert_eq!(target("kv/data/x?p=/../y"), "/v1/kv/data/x?p=/../y");

    assert_eq!(target("../x"), "/x");
    assert_eq!(target("../../../x"), "/x");

    let c = VaultClient::new(&cfg("https://v:8200/prefix/"), TOKEN);
    assert_eq!(c.request("kv/../x").unwrap().target, "/prefix/v1/x");
    assert_eq!(c.request("../../x").unwrap().target, "/x");

    assert_eq!(
        c.request("kv/../x").unwrap().url,
        "https://v:8200/prefix/v1/kv/../x"
    );
}

#[test]
fn encode_path_writes_every_byte_a_uri_cannot_hold() {
    assert_eq!(encoded("\"{}", PATH_SET), "%22%7B%7D");
    assert_eq!(encoded("a\u{7f}b", PATH_SET), "a%7Fb");
    assert_eq!(encoded("a\u{1}b\tc", PATH_SET), "a%01b%09c");
    assert_eq!(encoded("a b#c<d>e`f", PATH_SET), "a%20b%23c%3Cd%3Ee%60f");
    assert_eq!(encoded("a/b?c=%20&d", PATH_SET), "a/b%3Fc=%20&d");
}

#[test]
fn a_reference_splits_on_the_last_hash_and_refuses_an_empty_path() {
    let (p, f) = parse_reference(&settings(json!({ "path": "kv/data/a#b#c" }))).unwrap();
    assert_eq!((p.as_str(), f.as_str()), ("kv/data/a#b", "c"));
    let e = parse_reference(&settings(json!({ "path": "#k" }))).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
}

/// Every 3xx is the redirect refusal (and says why), 599 is still a server error and 600 is not;
/// the remaining non-success statuses use the generic refusal.
#[test]
fn status_classes_are_judged_at_their_edges() {
    for s in [301, 302, 303, 308] {
        let e = run(
            &Canned::status(s, ""),
            json!({ "path": "kv/data/openai#k" }),
        )
        .unwrap_err();
        assert_eq!(e.kind, SecretErrorKind::Internal, "{s}");
        assert!(
            e.message.contains("a redirect is not followed; set `addr`"),
            "{s}: {}",
            e.message
        );
    }
    let e = run(
        &Canned::status(599, ""),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Unavailable);
    assert!(e.message.contains("Vault server error"), "{}", e.message);
    let e = run(
        &Canned::status(600, ""),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Internal);
    assert!(!e.message.contains("server error"), "{}", e.message);
    for s in [200, 201] {
        let ok = Canned::status(s, &kv2(json!({ "k": "v" })));
        assert_eq!(
            run(&ok, json!({ "path": "kv/data/openai#k" })).unwrap(),
            b"v",
            "{s}"
        );
    }

    let e = run(
        &Canned::status(204, ""),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Internal);
    assert!(e.message.contains("is not valid JSON"), "{}", e.message);
}

#[test]
fn response_strings_and_non_string_material_keep_serde_json_semantics() {
    for value in [
        r#""plain""#,
        r#""é中🚀""#,
        r#""\"\\\/\b\f\n\r\t\u0000\u0020\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff\ud800\udc00\udbff\udfff""#,
        r#"{"z":"last","a":[null,true,false,17,-0.0],"\u007a":{"replaced":"new"}}"#,
        "[]",
        "{}",
        r#""null""#,
        "false",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775809",
        "1.25e+30",
        "1e308",
        "0e-100000",
    ] {
        let body =
            format!(r#"{{"data":null,"\u0064ata":{{"data":{{"k":"discard","\u006b":{value}}}}}}}"#);
        let reference: serde_json::Value = serde_json::from_str(&body).unwrap();
        let selected = &reference["data"]["data"]["k"];
        let expected = match selected.as_str() {
            Some(text) => text.as_bytes().to_vec(),
            None => serde_json::to_vec(selected).unwrap(),
        };
        let actual = judge(
            "kv/data/x",
            "k",
            "http://v/v1/kv/data/x",
            Ok(Response {
                status: 200,
                body_len: body.len(),
                body: body.into_bytes(),
            }),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn invalid_response_strings_numbers_and_nesting_are_still_refused() {
    let mut bodies: Vec<Vec<u8>> = [
        r#""\q""#,
        r#""\u12xz""#,
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\ud800\u0041""#,
        r#""\ud800\ud800""#,
        r#""\u123""#,
        "\"literal\nnewline\"",
        "01",
        "1e400",
        "1.",
        "+1",
        "[true,]",
        r#"{"nested":"secret","truncated":}"#,
    ]
    .into_iter()
    .map(|value| format!(r#"{{"data":{{"data":{{"k":{value}}}}}}}"#).into_bytes())
    .collect();
    bodies.push(b"{\"data\":{\"data\":{\"k\":\"invalid\xff\"}}}".to_vec());
    bodies.push(b"{\"data\":{\"data\":{\"invalid\xff\":1}}}".to_vec());
    for body in bodies {
        assert!(serde_json::from_slice::<serde_json::Value>(&body).is_err());
        let error = judge(
            "kv/data/x",
            "k",
            "http://v/v1/kv/data/x",
            Ok(Response {
                status: 200,
                body_len: body.len(),
                body,
            }),
        )
        .unwrap_err();
        assert_eq!(error.kind, SecretErrorKind::Internal);
        assert!(error.message.contains("is not valid JSON"));
    }

    for depth in [64, 124, 125, 126, 127, 128] {
        let body = format!(
            r#"{{"data":{{"data":{{"k":{}0{}}}}}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let expected = serde_json::from_str::<serde_json::Value>(&body);
        let actual = judge(
            "kv/data/x",
            "k",
            "http://v/v1/kv/data/x",
            Ok(Response {
                status: 200,
                body_len: body.len(),
                body: body.into_bytes(),
            }),
        );
        match expected {
            Ok(value) => assert_eq!(
                actual.unwrap(),
                serde_json::to_vec(&value["data"]["data"]["k"]).unwrap()
            ),
            Err(_) => assert_eq!(actual.unwrap_err().kind, SecretErrorKind::Internal),
        }
    }
}

#[test]
fn a_null_field_is_refused_invalid_naming_the_field() {
    let ex = Canned::status(200, &kv2(json!({ "k": null })));
    let e = run(&ex, json!({ "path": "kv/data/openai#k" })).unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert!(format!("{e:?}{e}").contains("\"k\""), "{e}");
}

#[test]
fn selected_string_null_and_nested_nulls_remain_valid_material() {
    for (selected, expected) in [
        (json!("null"), b"null".to_vec()),
        (
            json!({"array":[null,{"nested":null}]}),
            br#"{"array":[null,{"nested":null}]}"#.to_vec(),
        ),
    ] {
        let ex = Canned::status(200, &kv2(json!({"k":selected})));
        let got = run(&ex, json!({"path":"kv/data/openai#k"})).unwrap();
        assert_eq!(got, expected);
    }
}
