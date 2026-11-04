// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercise the production door and observe initialized config buffers through the same parser.

use std::ffi::c_void;

use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot, OpenIn, OpenOut, OpsHead, RefreshIn, ValidateIn,
};

use super::parse_config_observed as parse_config;
use super::probe;

const CONFIG: &[u8] =
    br#"{"addr":"https://svc:CANARY-userinfo@v:8200","token":{"env":"VAULT_TOKEN"}}"#;
const ESCAPED: &[u8] = br#"{"ad\u0064r":"https://svc:CANARY\u002duserinfo@v:8200","token":{"env":"VAULT\u005fTOKEN"}}"#;

fn input<I>(op: u32) -> InHead {
    // SAFETY: InHead is an ABI POD: null spans/context, Ticket::NONE and zero scalar fields
    // are its absent values. This initialized head is lent only for its synchronous crossing.
    let mut head: InHead = unsafe { std::mem::zeroed() };
    head.size = std::mem::size_of::<I>() as u32;
    head.op = op;
    head
}

fn output<O>() -> OutHead {
    // SAFETY: OutHead's all-zero POD representation is the ABI's blank/fault answer.
    let mut head: OutHead = unsafe { std::mem::zeroed() };
    head.size = std::mem::size_of::<O>() as u32;
    head
}

fn blob(bytes: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags,
    }
}

struct ActualDoor {
    ops: &'static OpsHead,
    instance: *mut c_void,
}

impl ActualDoor {
    fn new() -> Self {
        let door = crate::door::door();
        // SAFETY: this is this crate's own static SDK door, not an untrusted foreign address.
        let parts = unsafe { Door::read_parts(door) };
        // SAFETY: the secret Ops table begins with this live static lifecycle OpsHead.
        let ops = unsafe { &*parts.ops };
        Self {
            ops,
            instance: std::ptr::null_mut(),
        }
    }

    fn validate(&self, settings: &[u8]) -> Outcome {
        drop(parse_config(settings));
        let mut reason = [0_u8; 2048];
        let input = ValidateIn {
            head: input::<ValidateIn>(slot::VALIDATE),
            settings: blob(settings, BLOB_JSON, 0),
            err_buf: reason.as_mut_ptr(),
            err_cap: reason.len(),
        };
        let mut out = output::<OutHead>();
        // SAFETY: this crate's static lifecycle slot receives initialized, sized, aligned
        // heads. The settings bytes and exclusive error/output buffers remain alive for
        // synchronous validation, which retains no pointers into this frame.
        unsafe {
            (self.ops.validate.unwrap())(
                std::ptr::null_mut(),
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
        .outcome()
    }

    fn open(&mut self, settings: &[u8], token: &[u8]) -> Outcome {
        assert!(self.instance.is_null());
        drop(parse_config(settings));
        let material = [blob(token, BLOB_OCTETS, BLOB_SECRET)];
        let mut reason = [0_u8; 2048];
        let input = OpenIn {
            head: input::<OpenIn>(slot::OPEN),
            host: std::ptr::null(),
            settings: blob(settings, BLOB_JSON, 0),
            secrets: material.as_ptr(),
            secrets_len: material.len(),
            generation: 1,
            err_buf: reason.as_mut_ptr(),
            err_cap: reason.len(),
        };
        let mut out = OpenOut {
            head: output::<OpenOut>(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        };
        // SAFETY: this is the crate's live SDK open slot. The initialized, sized input/output
        // heads, settings, secret span array and token bytes remain alive through the call;
        // reason/out are exclusive writable storage. Vault::open copies configuration and
        // token into owned state, retaining none of these frame loans.
        let answered = unsafe {
            (self.ops.open.unwrap())(
                std::ptr::null_mut(),
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
        .outcome();
        self.instance = out.instance;
        answered
    }

    fn refresh(&self, settings: &[u8], token: &[u8]) -> Outcome {
        assert!(!self.instance.is_null());
        drop(parse_config(settings));
        let material = [blob(token, BLOB_OCTETS, BLOB_SECRET)];
        let input = RefreshIn {
            head: input::<RefreshIn>(slot::REFRESH),
            generation: 2,
            settings: blob(settings, BLOB_JSON, 0),
            secrets: material.as_ptr(),
            secrets_len: material.len(),
        };
        let mut out = output::<OutHead>();
        // SAFETY: this private fixture serially refreshes the instance this door opened.
        // The initialized, sized heads, settings, token and span array live through the
        // synchronous call. Vault::refresh copies the replacement state and retains no
        // frame loans; no resolve or other operation is concurrently in flight.
        unsafe {
            (self.ops.refresh.unwrap())(
                self.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
        .outcome()
    }
}

impl Drop for ActualDoor {
    fn drop(&mut self) {
        if !self.instance.is_null() {
            let input = input::<InHead>(slot::CLOSE);
            let mut out = output::<OutHead>();
            assert_eq!(
                // SAFETY: this is the sole close of the instance opened by this same static
                // door. All preceding lifecycle calls completed synchronously without
                // pending work; the initialized, sized heads live through close, and Drop
                // never uses the consumed instance again.
                unsafe {
                    (self.ops.close.unwrap())(
                        self.instance,
                        std::ptr::from_ref(&input).cast(),
                        std::ptr::from_mut(&mut out).cast(),
                    )
                }
                .outcome(),
                Outcome::Ready
            );
        }
    }
}

#[test]
fn observed_parser_wipes_userinfo_and_actual_lifecycle_accepts_config() {
    for config in [CONFIG, ESCAPED] {
        let observed = probe::Probe::start();
        let mut door = ActualDoor::new();
        assert_eq!(door.validate(config), Outcome::Ready);
        assert_eq!(door.open(config, b"resolved-token"), Outcome::Ready);
        assert_eq!(door.refresh(config, b"rotated-token"), Outcome::Ready);
        drop(door);
        observed
            .finish()
            .assert_wiped(&["parse view", "parsed value"]);
    }
}

#[test]
fn config_clones_wipe_their_own_userinfo_and_nested_token_payloads() {
    let observed = probe::Probe::start();
    let config = parse_config(ESCAPED).unwrap();
    let cloned = config.clone();
    super::watch_config(&cloned);
    assert_eq!(config.addr, cloned.addr);
    let request = crate::VaultClient::new(&cloned, b"resolved-token")
        .request("kv/data/x")
        .unwrap();
    assert_eq!(request.url, "https://v:8200/v1/kv/data/x");
    assert_eq!(request.fields.len(), 1);
    assert_eq!(request.fields[0].0, "X-Vault-Token");
    drop(request);
    drop(config);
    drop(cloned);
    let report = observed.finish();
    assert_eq!(report.allocations_for("config address"), 1);
    report.assert_wiped(&["parsed value"]);
}

#[test]
fn observed_parser_wipes_refusals_and_actual_door_also_refuses() {
    for config in [
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"timeout_secs":0}"#.as_slice(),
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"ca_cert_pem":"not a certificate"}"#,
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"timeout_secs":"wrong type"}"#,
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"unknown":[1,2]}"#,
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"addr":"https://v"}"#,
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"truncated":}"#,
        br#"{"addr":"https://svc:CANARY\u002duserinfo\q@v","token":{"env":"T"}}"#,
    ] {
        let observed = probe::Probe::start();
        let mut door = ActualDoor::new();
        assert_eq!(door.validate(config), Outcome::Failed);
        assert_eq!(door.open(config, b"resolved-token"), Outcome::Failed);
        drop(door);
        observed.finish().assert_wiped(&["parsed value"]);
    }
}

#[test]
fn observed_config_is_wiped_and_actual_token_refusals_hold() {
    let mut door = ActualDoor::new();
    assert_eq!(door.open(CONFIG, b"resolved-token"), Outcome::Ready);
    for token in [b"".as_slice(), b"invalid\ntoken"] {
        let observed = probe::Probe::start();
        let mut unopened = ActualDoor::new();
        assert_eq!(unopened.open(ESCAPED, token), Outcome::Failed);
        assert_eq!(door.refresh(ESCAPED, token), Outcome::Failed);
        drop(unopened);
        observed.finish().assert_wiped(&["parsed value"]);
    }
}

#[test]
fn the_original_config_decoder_exposes_real_unwiped_escaped_scratch() {
    let observed = probe::Probe::start();
    let result = super::observe_original_parse(
        br#"{"addr":"https://svc:CANARY\u002duserinfo@v","token":{"env":"T"},"truncated":}"#,
    );
    assert!(result.is_err());
    drop(result);
    observed.finish().assert_unwiped("parser scratch");
}
