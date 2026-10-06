// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's instance: a resolve answers the material, FAILED with its kind, or PENDING while the
//! exchange runs; `open`/`refresh` take the token from the lent secrets; the Statement names the
//! token as its one secret reference. What the slots write (the lease, the secret flag, the error
//! kind and text) is held over the real loader, linked and dropped in, in the plugin crate's
//! `tests/conformance.rs`.

use super::*;
use busbar_contract::abi::secret::{ERROR_KIND_DENIED, ERROR_KIND_INVALID, ERROR_KIND_UNAVAILABLE};
use busbar_contract::secret::SecretErrorKind;
use serde_json::json;
use std::sync::Mutex;

const T: Ticket = Ticket {
    slot: 1,
    generation: 1,
};

/// An exchange answering `status` + `body` after `pends` pending answers.
struct Scripted {
    status: u16,
    body: String,
    pends: Mutex<u32>,
}

impl Exchange for Scripted {
    fn exchange(&self, _: (u32, u32), _: &Request) -> Exchanged {
        let mut p = self.pends.lock().unwrap();
        if *p > 0 {
            *p -= 1;
            return Exchanged::Pending;
        }
        Exchanged::Done(Ok(crate::Response {
            status: self.status,
            body: self.body.clone().into_bytes(),
            body_len: self.body.len(),
        }))
    }
}

const SETTINGS: &[u8] = br#"{"addr":"http://v:8200","token":{"env":"T"}}"#;

fn vault(status: u16, body: &str, pends: u32) -> Vault {
    let cfg = crate::parse_config(SETTINGS).unwrap();
    Vault::new(
        VaultClient::new(&cfg, b"tok"),
        Box::new(Scripted {
            status,
            body: body.into(),
            pends: Mutex::new(pends),
        }),
    )
}

const OK_BODY: &str = r#"{"data":{"data":{"k":"material"}}}"#;

fn reference() -> Vec<u8> {
    json!({ "path": "kv/data/x#k" }).to_string().into_bytes()
}

#[test]
fn a_read_answers_the_material() {
    let v = vault(200, OK_BODY, 0);
    assert_eq!(v.resolve(T, &reference()).unwrap().unwrap(), b"material");
}

#[test]
fn a_refusal_answers_its_kind() {
    let v = vault(403, "denied", 0);
    let e = v.resolve(T, &reference()).unwrap().unwrap_err();
    assert_eq!(error_kind(e.kind), ERROR_KIND_DENIED);
    assert!(!e.message.is_empty(), "a refusal names its reason");

    let e = v.resolve(T, b"[not an object]").unwrap().unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}

#[test]
fn a_pending_exchange_pends_the_op_and_the_resume_answers() {
    let v = vault(200, OK_BODY, 1);
    assert!(v.resolve(T, &reference()).is_none(), "pending");
    assert_eq!(v.resolve(T, &reference()).unwrap().unwrap(), b"material");
}

#[test]
fn the_host_exchange_names_the_missing_http_exchange() {
    let v = Vault::open(SETTINGS, &[&b"tok"[..]], 1).expect("opens");
    let e = v.resolve(T, &reference()).unwrap().unwrap_err();
    assert_eq!(error_kind(e.kind), ERROR_KIND_UNAVAILABLE);
}

#[test]
fn open_and_refresh_need_the_token_material() {
    for secrets in [&[][..], &[&b""[..]][..]] {
        let r = Vault::open(SETTINGS, secrets, 1).expect_err("no token, no instance");
        assert_eq!(r.outcome(), Outcome::Failed);
        assert_eq!(
            r.text(),
            Some("invalid hashicorp-vault plugin config: `token` resolved to no secret material")
        );
    }
    let v = Vault::open(SETTINGS, &[&b"tok"[..]], 1).expect("opens");
    assert!(v.refresh(b"{}", &[&b"tok"[..]], 2).is_err(), "a bad reload");
    assert!(v.refresh(SETTINGS, &[], 2).is_err(), "no token");
    assert!(v.refresh(SETTINGS, &[&b"tok2"[..]], 2).is_ok());
    assert!(Vault::validate(b"").is_err());
    assert!(Vault::validate(SETTINGS).is_ok());
}

#[test]
fn the_statement_names_the_plugin_and_its_token_reference() {
    assert_eq!(STATEMENT.secret_refs_len, 1);
    assert_eq!(STATEMENT.name.len, crate::NAME.len());
    assert_eq!(STATEMENT.max_inflight, 64);
}

/// The framed request names the read's path and query, never the authority (that is the need's).
#[test]
fn the_framed_request_names_the_path() {
    assert_eq!(
        super::path_of("https://vault.internal:8200/v1/kv/data/x?version=2"),
        "/v1/kv/data/x?version=2"
    );
    assert_eq!(super::path_of("not a url"), "/");
}
