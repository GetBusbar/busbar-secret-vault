// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's instance: a resolve answers the material, FAILED with its kind, or PENDING while the
//! exchange runs; `open`/`refresh` take the token from the lent secrets; the Statement names the
//! token as its one secret reference. What the slots write (the lease, the secret flag, the error
//! kind and text) is held over the real loader, linked and dropped in, in the plugin crate's
//! `tests/conformance.rs`.

use super::*;
use busbar_contract::abi::sdk::secret::error_kind;
use busbar_contract::abi::secret::{ERROR_KIND_DENIED, ERROR_KIND_INVALID};
use busbar_contract::secret::SecretErrorKind;
use serde_json::json;
use std::sync::Mutex;

/// An exchange answering `status` + `body` after `pends` pending answers.
struct Scripted {
    status: u16,
    body: String,
    pends: Mutex<u32>,
}

impl Exchange for Scripted {
    fn exchange(&self, _: &Request) -> Exchanged {
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

/// A vault and the exchange a test stands in for the host's (prod resolves only through the op's
/// [`HostExchange`]).
struct Rig<E> {
    vault: Vault,
    exchange: E,
}

impl<E: Exchange> Rig<E> {
    fn resolve(&self, settings: &[u8]) -> Option<SecretResult<Vec<u8>>> {
        self.vault.resolve(&self.exchange, settings)
    }
}

impl<E> std::ops::Deref for Rig<E> {
    type Target = Vault;
    fn deref(&self) -> &Vault {
        &self.vault
    }
}

fn vault(status: u16, body: &str, pends: u32) -> Rig<Scripted> {
    let cfg = crate::parse_config(SETTINGS).unwrap();
    Rig {
        vault: Vault::new(VaultClient::new(&cfg, b"tok")),
        exchange: Scripted {
            status,
            body: body.into(),
            pends: Mutex::new(pends),
        },
    }
}

const OK_BODY: &str = r#"{"data":{"data":{"k":"material"}}}"#;

fn reference() -> Vec<u8> {
    json!({ "path": "kv/data/x#k" }).to_string().into_bytes()
}

#[test]
fn a_read_answers_the_material() {
    let v = vault(200, OK_BODY, 0);
    assert_eq!(v.resolve(&reference()).unwrap().unwrap(), b"material");
}

#[test]
fn a_refusal_answers_its_kind() {
    let v = vault(403, "denied", 0);
    let e = v.resolve(&reference()).unwrap().unwrap_err();
    assert_eq!(error_kind(e.kind), ERROR_KIND_DENIED);
    assert!(!e.message.is_empty(), "a refusal names its reason");

    let e = v.resolve(b"[not an object]").unwrap().unwrap_err();
    assert_eq!(e.kind, SecretErrorKind::Invalid);
    assert_eq!(error_kind(e.kind), ERROR_KIND_INVALID);
}

#[test]
fn a_pending_exchange_pends_the_op_and_the_resume_answers() {
    let v = vault(200, OK_BODY, 1);
    assert!(v.resolve(&reference()).is_none(), "pending");
    assert_eq!(v.resolve(&reference()).unwrap().unwrap(), b"material");
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
    let r = v
        .refresh(b"{}", &[&b"tok"[..]], 2)
        .expect_err("a bad reload");
    assert_eq!(r.outcome(), Outcome::Failed);
    assert_eq!(
        r.text(),
        Some("invalid hashicorp-vault plugin config: missing field `addr` at line 1 column 2")
    );
    let r = v.refresh(SETTINGS, &[], 2).expect_err("no token");
    assert_eq!(r.outcome(), Outcome::Failed);
    assert_eq!(
        r.text(),
        Some("invalid hashicorp-vault plugin config: `token` resolved to no secret material")
    );
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

/// Records the `X-Vault-Token` of each request it answers.
struct Recording {
    tokens: std::sync::Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Exchange for Recording {
    fn exchange(&self, r: &Request) -> Exchanged {
        let token = r
            .fields
            .iter()
            .find(|(n, _)| *n == "X-Vault-Token")
            .map(|(_, v)| v.to_vec())
            .unwrap_or_default();
        self.tokens.lock().unwrap().push(token);
        Exchanged::Done(Ok(crate::Response {
            status: 200,
            body: OK_BODY.as_bytes().to_vec(),
            body_len: OK_BODY.len(),
        }))
    }
}

/// A refresh swaps the client (the next read carries the new token); a refused refresh keeps the
/// running one.
#[test]
fn a_refresh_swaps_the_client_and_a_refused_refresh_keeps_it() {
    let tokens = std::sync::Arc::new(Mutex::new(Vec::new()));
    let cfg = crate::parse_config(SETTINGS).unwrap();
    let v = Rig {
        vault: Vault::new(VaultClient::new(&cfg, b"tok1")),
        exchange: Recording {
            tokens: tokens.clone(),
        },
    };
    assert!(v.refresh(SETTINGS, &[&b"tok2"[..]], 2).is_ok());
    assert_eq!(v.resolve(&reference()).unwrap().unwrap(), b"material");
    assert!(v.refresh(b"{}", &[&b"tok3"[..]], 3).is_err());
    assert_eq!(v.resolve(&reference()).unwrap().unwrap(), b"material");
    assert_eq!(
        *tokens.lock().unwrap(),
        vec![b"tok2".to_vec(), b"tok2".to_vec()]
    );
}

/// The need a request goes over carries the CA exactly when the request names one, and both needs
/// are the operator-infrastructure outbound `http` need to `settings.addr`. Read through `NEEDS`
/// (what the Statement declares), not the constants, so swapped constants fail.
#[test]
fn the_needs_and_the_need_selection() {
    let c = VaultClient::new(&crate::parse_config(SETTINGS).unwrap(), b"tok");
    let without = c.request("kv/data/x").unwrap();
    let mut with_cfg = crate::parse_config(SETTINGS).unwrap();
    with_cfg.ca_cert_pem = Some("-----BEGIN CERTIFICATE-----".into());
    let with_pem = VaultClient::new(&with_cfg, b"tok")
        .request("kv/data/x")
        .unwrap();

    let trusted = &NEEDS[need_for(&with_pem) as usize];
    assert_eq!(trusted.trust_from.len, "settings.ca_cert_pem".len());
    assert!(!trusted.trust_from.ptr.is_null());
    let public = &NEEDS[need_for(&without) as usize];
    assert!(public.trust_from.ptr.is_null());

    assert_eq!(STATEMENT.needs, NEEDS.as_ptr());
    assert_eq!(STATEMENT.needs_len, 2);
    assert_eq!(NEEDS.len(), 2);
    for n in NEEDS {
        assert_eq!(n.target_from.len, "settings.addr".len());
        assert!(!n.target_from.ptr.is_null());
        assert_eq!(n.transport.len, "http".len());
        assert_eq!(n.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE);
        assert_eq!(n.direction, DIRECTION_OUTBOUND);
        assert_eq!(n.keep_mode, KEEP_NAMED);
    }
}

/// A token with a line break in it can never be sent (the exchange refuses the head field), so it
/// is refused at open and refresh, naming the setting and the reason, never the value.
#[test]
fn a_token_with_a_line_break_is_refused_at_open_and_refresh() {
    let text = "invalid hashicorp-vault plugin config: `token` resolved to material with a line \
                break (CR or LF), which cannot be sent as the X-Vault-Token header";
    let v = Vault::open(SETTINGS, &[&b"tok"[..]], 1).expect("opens");
    for bad in [&b"ab\ncd"[..], b"ab\r\ncd", b"ab\rcd", b"abcd\n"] {
        let r = Vault::open(SETTINGS, &[bad], 1).expect_err("a line break is refused");
        assert_eq!(r.outcome(), Outcome::Failed);
        assert_eq!(r.text(), Some(text));
        let r = v.refresh(SETTINGS, &[bad], 2).expect_err("and at refresh");
        assert_eq!(r.outcome(), Outcome::Failed);
        assert_eq!(r.text(), Some(text));
    }
}

/// The cut `HostExchange` applies to the host's reply (the fake host cannot drive a framed
/// exchange, so the cut is the seam): at the cap the body is whole, one past it is cut to the cap
/// and the full length is kept for the judge.
#[test]
fn the_reply_is_cut_at_the_body_cap() {
    let cap = crate::MAX_VAULT_RESPONSE_BYTES;
    for (len, kept) in [(cap, cap), (cap + 1, cap), (3, 3), (0, 0)] {
        let r = cut_to_cap(
            sdk::ExchangeResponse {
                status: 200,
                body: vec![b'x'; len],
                ..Default::default()
            },
            cap,
        );
        assert_eq!((r.status, r.body.len(), r.body_len), (200, kept, len));
    }
    // The request's own cap is one past the maximum, so an at-the-maximum reply is never "over".
    let c = VaultClient::new(&crate::parse_config(SETTINGS).unwrap(), b"tok");
    assert_eq!(c.request("kv/data/x").unwrap().body_cap, cap + 1);
}
