// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests for the sans-IO Vault KV v2 client: reference-parsing (both
//! field-addressing forms), the request it builds, every 1.5.5 response class and text, the body cap,
//! a pending exchange, and — gated on `BUSBAR_TEST_VAULT_ADDR`/`BUSBAR_TEST_VAULT_TOKEN`
//! — a real round trip against a live Vault dev-mode server.

use super::*;
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
    // Deliberately adversarial: a `#` that is not the intended split point.
    let s = settings(json!({ "path": "kv/data/weird#name", "field": "real_field" }));
    let (path, field) = parse_reference(&s).unwrap();
    assert_eq!(path, "kv/data/weird#name");
    assert_eq!(field, "real_field");
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
/// `secret/data/busbar-test` directly via a raw HTTP PUT (a read-only client can't test itself
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

    // Seed a real secret with two fields directly via Vault's KV v2 write endpoint — this test's
    // own setup, not part of the crate's (read-only) public API.
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

    // `#field` addressing (the published doc convention).
    let hash_settings = settings(json!({ "path": "secret/data/busbar-test#api_key" }));
    let got = module
        .resolve(&hash_settings, &ex, T)
        .unwrap()
        .expect("resolve api_key");
    assert_eq!(got, b"sk-live-abc123");

    // Explicit `field` key addressing the SECOND field in the same entry.
    let explicit_settings =
        settings(json!({ "path": "secret/data/busbar-test", "field": "org_id" }));
    let got = module
        .resolve(&explicit_settings, &ex, T)
        .unwrap()
        .expect("resolve org_id");
    assert_eq!(got, b"org-xyz");

    // A wrong path is a distinct, loud 404 — never an empty Ok.
    let missing = settings(json!({ "path": "secret/data/no-such-secret#x" }));
    let err = module.resolve(&missing, &ex, T).unwrap().unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::NotFound);
    assert!(
        err.message.contains("404"),
        "expected a 404 error, got: {}",
        err.message
    );

    // A wrong field on a REAL path is also a distinct, loud error naming the field.
    let bad_field = settings(json!({ "path": "secret/data/busbar-test#no_such_field" }));
    let err = module.resolve(&bad_field, &ex, T).unwrap().unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::NotFound);
    assert!(
        err.message.contains("no_such_field"),
        "got: {}",
        err.message
    );

    // A bad token is a distinct, loud 403 — never conflated with the 404 path.
    let bad = VaultClient::new(&cfg(&addr), b"not-a-real-token");
    let err = bad.resolve(&hash_settings, &ex, T).unwrap().unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Denied);
    assert!(
        err.message.contains("403"),
        "expected a 403 error, got: {}",
        err.message
    );
}

// ── the sans-IO client ──────────────────────────────────────────────────────────────────────────

/// The ticket every test op runs on.
const T: (u32, u32) = (1, 1);

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
/// module held one.
struct ReqwestExchange;

impl Exchange for ReqwestExchange {
    fn exchange(&self, _: (u32, u32), r: &Request) -> Exchanged {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(r.timeout_ms))
            .build()
            .expect("client");
        let mut req = client.get(&r.url);
        for (n, v) in &r.fields {
            req = req.header(*n, v.as_slice());
        }
        Exchanged::Done(match req.send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
                let body_len = body.len();
                let body = body[..body_len.min(r.body_cap)].to_vec();
                Ok(Response {
                    status,
                    body,
                    body_len,
                })
            }
            Err(e) => Err(e.to_string()),
        })
    }
}

/// An exchange answering one canned response (or transport failure), recording the request.
struct Canned {
    answer: Result<Response, String>,
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

    fn of(answer: Result<Response, String>) -> Self {
        Self {
            answer,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Exchange for Canned {
    fn exchange(&self, _: (u32, u32), r: &Request) -> Exchanged {
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
        .resolve(&settings(reference), ex, T)
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
    let r = c.request("/kv/data/openai");
    assert_eq!(r.method, "GET");
    assert_eq!(
        r.url, URL,
        "trailing slash trimmed once, leading slash of the path trimmed"
    );
    assert_eq!(r.fields, vec![("X-Vault-Token", TOKEN.to_vec())]);
    assert_eq!(r.timeout_ms, 10_000);
    assert_eq!(r.body_cap, MAX_VAULT_RESPONSE_BYTES + 1);
    assert!(r.trust_pem.is_none());
    let shown = format!("{r:?} {c:?}");
    assert!(
        !shown.contains("never-in-a-message"),
        "Debug prints the token: {shown}"
    );
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

/// Every 1.5.5 class, its kind and its text byte for byte (the 1.5.5 module's format strings).
#[test]
fn every_response_class_answers_1_5_5s_kind_and_text() {
    let p = "\"kv/data/openai\"";
    let cases: Vec<(Canned, SecretErrorKind, String)> = vec![
        (
            Canned::of(Err("connection refused".into())),
            SecretErrorKind::Unavailable,
            format!("request to Vault ({URL}) failed: error sending request for url ({URL})"),
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
            format!("Vault returned HTTP 400 Bad Request reading path {p} ({URL}): bad request body"),
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
            format!(
                "Vault secret at path {p} has no field \"api_key\"; available fields: [\"a\", \"b\"]"
            ),
        ),
    ];
    for (ex, kind, text) in cases {
        let e = run(&ex, json!({ "path": "kv/data/openai#api_key" })).unwrap_err();
        assert_eq!((e.kind, e.message.as_str()), (kind, text.as_str()));
    }
}

#[test]
fn a_non_2xx_excerpt_is_the_first_300_characters() {
    let long = "é".repeat(400);
    let e = run(
        &Canned::status(418, &long),
        json!({ "path": "kv/data/openai#k" }),
    )
    .unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Internal);
    assert!(e
        .message
        .starts_with("Vault returned HTTP 418 I'm a teapot reading path"));
    assert!(e.message.ends_with(&"é".repeat(300)));
    assert!(!e.message.ends_with(&"é".repeat(301)));
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
    // A host that fills only the cap but reports the full length is judged by the length.
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
    // Exactly at the cap is read (and judged on its content).
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
    // 1.5.5 classifies 404/403/5xx before it reads the body: an oversize 404 is still a 404.
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

/// An exchange that pends once, then answers: the op answers "not yet", and the re-invoked op
/// on the same ticket receives the stored result without a second request.
struct PendsOnce {
    calls: std::sync::Mutex<u32>,
}

impl Exchange for PendsOnce {
    fn exchange(&self, _: (u32, u32), _: &Request) -> Exchanged {
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
    assert!(c.resolve(&s, &ex, T).is_none(), "pending");
    assert_eq!(c.resolve(&s, &ex, T).unwrap().unwrap(), b"late");
}

#[test]
fn config_parses_with_1_5_5s_refusals() {
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
        e.starts_with("invalid hashicorp-vault plugin config: key must be a string"),
        "{e}"
    );
    let e = parse_config(br#"{"addr":"http://v"}"#).unwrap_err();
    assert_eq!(
        e,
        "invalid hashicorp-vault plugin config: missing field `token` at line 1 column 19"
    );
    let e = parse_config(br#"{"token":"t"}"#).unwrap_err();
    assert_eq!(
        e,
        "invalid hashicorp-vault plugin config: missing field `addr` at line 1 column 13"
    );
    let e = parse_config(br#"{"addr":"http://v","token":"t","tls":true}"#).unwrap_err();
    assert!(e.contains("unknown field `tls`"), "{e}");
    let c = parse_config(br#"{"addr":"http://v","token":{"env":"T"},"timeout_secs":3}"#).unwrap();
    assert_eq!(
        (c.addr.as_str(), c.timeout_secs, c.ca_cert_pem),
        ("http://v", 3, None)
    );
    assert_eq!(
        parse_config(br#"{"addr":"a","token":"t"}"#)
            .unwrap()
            .timeout_secs,
        10
    );
}

#[test]
fn the_extra_root_and_timeout_ride_the_request() {
    let mut c = cfg(ADDR);
    c.ca_cert_pem = Some("-----BEGIN CERTIFICATE-----".into());
    c.timeout_secs = 3;
    let r = VaultClient::new(&c, TOKEN).request("kv/data/x");
    assert_eq!(r.trust_pem.as_deref(), Some("-----BEGIN CERTIFICATE-----"));
    assert_eq!(r.timeout_ms, 3000);
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
