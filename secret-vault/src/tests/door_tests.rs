// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's instance: a resolve answered READY under a lease, FAILED with its code and text, or
//! PENDING while the exchange runs; release zeroes and forgets; the Statement names the token as
//! its one secret reference. The door over the real loader, linked and dropped in, is the plugin
//! crate's `tests/conformance.rs`.

use super::*;
use busbar_contract::abi::mechanism::call::{Envelope, RawOutcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::secret::{ERROR_KIND_DENIED, ERROR_KIND_INVALID};
use serde_json::json;

const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

fn head(slot: u32) -> InHead {
    InHead {
        size: std::mem::size_of::<InHead>() as u32,
        op: 0,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        ticket: Ticket {
            slot,
            generation: 1,
        },
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: NO_BLOB,
    }
}

fn out() -> ResolveOut {
    ResolveOut {
        head: OutHead {
            size: std::mem::size_of::<ResolveOut>() as u32,
            outcome: RawOutcome(0),
            _reserved: [0; 3],
            wake_at_ns: 0,
            lease: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            envelope: Envelope {
                metrics: std::ptr::null(),
                metrics_len: 0,
                diags: std::ptr::null(),
                diags_len: 0,
            },
            extensions: NO_BLOB,
        },
        secret: NO_BLOB,
        error_kind: 0,
        _reserved: 0,
    }
}

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

fn vault(status: u16, body: &str, pends: u32) -> Vault {
    let cfg = crate::parse_config(br#"{"addr":"http://v:8200","token":{"env":"T"}}"#).unwrap();
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

#[test]
fn a_read_is_ready_under_a_lease_and_release_zeroes_and_forgets_it() {
    let v = vault(200, OK_BODY, 0);
    let mut o = out();
    let settings = json!({ "path": "kv/data/x#k" }).to_string();
    assert_eq!(
        v.resolve(&head(1), settings.as_bytes(), &mut o),
        Outcome::Ready
    );
    assert_eq!(o.head.lease, 1);
    assert_eq!(o.secret.len, b"material".len());
    assert_eq!(o.secret.flags, BLOB_SECRET);
    assert_eq!(o.error_kind, ERROR_KIND_UNSET);
    assert_eq!(v.leases().held(), 1);
    assert_eq!(v.leases().release(1), Outcome::Ready);
    assert_eq!(v.leases().held(), 0);
    // RED: a lease released twice, or never granted, is refused.
    assert_eq!(v.leases().release(1), Outcome::Refused);
    assert_eq!(v.leases().release(99), Outcome::Refused);
}

#[test]
fn a_refusal_is_failed_with_its_code_and_no_material() {
    let v = vault(403, "denied", 0);
    let mut o = out();
    let s = json!({ "path": "kv/data/x#k" }).to_string();
    assert_eq!(v.resolve(&head(2), s.as_bytes(), &mut o), Outcome::Failed);
    assert_eq!(o.error_kind, ERROR_KIND_DENIED);
    assert!(o.secret.ptr.is_null());
    assert_eq!(o.head.lease, 0);
    assert!(o.head.error.len > 0, "a refusal names its reason");
    assert_eq!(v.leases().held(), 0);

    let mut o = out();
    assert_eq!(
        v.resolve(&head(3), b"[not an object]", &mut o),
        Outcome::Failed
    );
    assert_eq!(o.error_kind, ERROR_KIND_INVALID);
}

#[test]
fn a_pending_exchange_pends_the_op_and_the_resume_answers() {
    let v = vault(200, OK_BODY, 1);
    let s = json!({ "path": "kv/data/x#k" }).to_string();
    let mut o = out();
    assert_eq!(v.resolve(&head(4), s.as_bytes(), &mut o), Outcome::Pending);
    assert_eq!(o.head.lease, 0);
    assert_eq!(v.resolve(&head(4), s.as_bytes(), &mut o), Outcome::Ready);
    assert_eq!(o.secret.len, 8);
}

#[test]
fn empty_material_is_ready_with_no_lease() {
    let v = vault(200, r#"{"data":{"data":{"k":""}}}"#, 0);
    let mut o = out();
    let s = json!({ "path": "kv/data/x#k" }).to_string();
    assert_eq!(v.resolve(&head(5), s.as_bytes(), &mut o), Outcome::Ready);
    assert_eq!((o.head.lease, o.secret.len), (0, 0));
}

#[test]
fn the_host_exchange_names_the_missing_http_exchange() {
    let cfg = crate::parse_config(br#"{"addr":"http://v:8200","token":"t"}"#).unwrap();
    let v = Vault::new(VaultClient::new(&cfg, b"tok"), Box::new(HostExchange));
    let mut o = out();
    let s = json!({ "path": "kv/data/x#k" }).to_string();
    assert_eq!(v.resolve(&head(6), s.as_bytes(), &mut o), Outcome::Failed);
    assert_eq!(
        o.error_kind,
        busbar_contract::abi::secret::ERROR_KIND_UNAVAILABLE
    );
}

#[test]
fn the_statement_names_the_plugin_and_its_token_reference() {
    assert_eq!(STATEMENT.secret_refs_len, 1);
    assert_eq!(STATEMENT.name.len, crate::NAME.len());
    assert_eq!(STATEMENT.max_inflight, 64);
}

#[test]
fn held_texts_are_kept_once_and_never_move() {
    let a = held("one refusal".into());
    let b = held("one refusal".into());
    assert_eq!((a.ptr, a.len), (b.ptr, b.len));
    assert_ne!(held("another".into()).ptr, a.ptr);
}
