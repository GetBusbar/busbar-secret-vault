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
            format!(
                "request to Vault ({URL}) failed: error sending request for url ({URL}): \
                 connection refused"
            ),
        ),
        (
            Canned::of(Err("  \n".into())),
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

/// No text of Vault's reply reaches a refusal (sibling review 2026-10-25, owner rule: no vault reply
/// text in any error): not a non-2xx body (RED before: its first 300 characters were quoted), not
/// the names of the fields a secret holds (RED before: "available fields: [..]").
#[test]
fn no_text_of_the_reply_reaches_a_refusal() {
    for status in [400, 418, 429] {
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
/// set, rather than a bare status.
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
/// RED before: it resolved READY with no material.
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
/// are refused INVALID before any request (RED before: ignored, and a blank path sent `GET /v1/`).
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
/// `ca_cert_pem` with no certificate and a `timeout_secs` of 0 are refused at validate/open/refresh,
/// naming the key and never quoting the value (RED before: all three opened).
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

/// `Debug` of a response never prints its body, and of a config never its token reference or the
/// address's userinfo (RED before: both were derived).
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

/// 1.5.5 judges the body cap before any other non-2xx: an over-cap 400 or 418 is the cap refusal,
/// while an over-cap 403 and 503 keep their own classes.
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
        parse_config(br#"{"addr":"http://a","token":"t"}"#)
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
    let r = VaultClient::new(&c, TOKEN)
        .request("kv/data/x")
        .expect("a valid URL");
    assert_eq!(r.trust_pem.as_deref(), Some("-----BEGIN CERTIFICATE-----"));
    assert_eq!(r.timeout_ms, 3000);
}

/// The framed target is the path and query, `addr`'s own prefix included, the path carried verbatim
/// (bytes a URI cannot hold percent-encoded; `?` still starts the query).
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
    // A `#` that is part of the path (the `field` key form) is data, not a fragment.
    let ex = Canned::status(200, &kv2(json!({ "k": "v" })));
    let got = c
        .resolve(
            &settings(json!({ "path": "kv/data/a#b", "field": "k" })),
            &ex,
            T,
        )
        .unwrap();
    assert_eq!(got.unwrap(), b"v");
    assert_eq!(target("kv/data/a#b"), "/v1/kv/data/a%23b");
    // The display URL stays the raw form.
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
        .resolve(&settings(json!({ "path": "kv/data/x#k" })), &ex, T)
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
            .resolve(&reference, &Canned::status(404, "{}"), T)
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

// ── Credential-echo canaries (CREDENTIAL-LOCKDOWN H4, A.3) ──────────────────────────────────────

const CANARY: &str = "CANARY3b90e4";

/// H4: a non-2xx answer whose body is a KV payload (a proxy or a standby answering a read with a
/// status Vault does not use for success) carried sibling secret values into the refusal excerpt.
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
    // Vault's own error envelope is not quoted either (sibling review 2026-10-25: no text of
    // Vault's reply reaches a refusal); the status says what happened.
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
/// the `addr` userinfo and the token reference as written.
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
    // `Vec<u8>`'s `Debug` prints the bytes as numbers: look for those too.
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
