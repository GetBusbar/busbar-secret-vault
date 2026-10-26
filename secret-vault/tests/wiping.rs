// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every heap block the plugin frees while it resolves a reference must have been wiped first: the
//! token's copy in the request, the response body, the parsed JSON tree, and the resolved value
//! itself once its answer drops (the credential chip, row 6: host-owned secret bytes; the value is
//! held in a zeroizing holder until the SDK writes it into the host's buffer). This test binary
//! installs a global allocator whose `dealloc` scans the block being freed for two canaries (the
//! token and a secret value) and records whether it saw either. It is its own binary so the crate's
//! `forbid(unsafe_code)` does not apply to the allocator wrapper.
//!
//! Residual (not covered, and not claimable): serde_json keeps a private scratch buffer for strings
//! that contain JSON escapes, which safe code cannot wipe; the canary body here has no escapes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use busbar_secret_vault::{
    parse_config, Exchange, Exchanged, Request, Response, VaultClient, MAX_VAULT_RESPONSE_BYTES,
};

const TOKEN: &[u8] = b"s.CANARY-TOKEN-7f3a";
const VALUE: &[u8] = b"CANARY-VALUE-91c2";

static SAW_TOKEN: AtomicBool = AtomicBool::new(false);
static SAW_VALUE: AtomicBool = AtomicBool::new(false);

/// A naive byte search; allocates nothing.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

struct Scanning;

// SAFETY: every call forwards unchanged to `System`; `dealloc` only reads the block it is about to
// free (and `realloc` is the trait's default, so a grown block's old storage also reaches `dealloc`).
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let block = std::slice::from_raw_parts(ptr, layout.size());
        if contains(block, TOKEN) {
            SAW_TOKEN.store(true, Ordering::SeqCst);
        }
        if contains(block, VALUE) {
            SAW_VALUE.store(true, Ordering::SeqCst);
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

/// Answers the prepared 200 body by moving it into the response; copies nothing of the request.
struct Moves {
    body: Mutex<Option<Vec<u8>>>,
}

impl Exchange for Moves {
    fn exchange(&self, _: (u32, u32), _: &Request) -> Exchanged {
        let body = self.body.lock().unwrap().take().expect("one exchange");
        let body_len = body.len();
        Exchanged::Done(Ok(Response {
            status: 200,
            body,
            body_len,
        }))
    }
}

#[test]
fn nothing_the_plugin_frees_still_holds_the_token_or_the_value() {
    let cfg = parse_config(br#"{"addr":"http://v:8200","token":{"env":"T"}}"#).unwrap();
    let settings = serde_json::json!({ "path": "kv/data/x#k" })
        .as_object()
        .unwrap()
        .clone();

    // The body is built in a buffer large enough that it never grows, so no growth frees a partial copy; it is then moved
    // (never copied) into the response, which owns it from there.
    let mut body: Vec<u8> = Vec::with_capacity(128);
    body.extend_from_slice(br#"{"data":{"data":{"k":""#);
    body.extend_from_slice(VALUE);
    body.extend_from_slice(br#"","other":""#);
    body.extend_from_slice(VALUE);
    body.extend_from_slice(br#""}}}"#);
    assert!(body.len() < MAX_VAULT_RESPONSE_BYTES);
    let exchange = Moves {
        body: Mutex::new(Some(body)),
    };

    // Setup allocated (and freed) nothing that holds a canary the plugin owns, but reset the flags
    // anyway so only what happens from the resolve on is judged.
    SAW_TOKEN.store(false, Ordering::SeqCst);
    SAW_VALUE.store(false, Ordering::SeqCst);

    {
        let client = VaultClient::new(&cfg, TOKEN);
        // The plugin's answer, dropped as the door drops it: nothing here wipes it on the
        // plugin's behalf. RED while `resolve` answered a plain `Vec<u8>`.
        let material = client
            .resolve(&settings, &exchange, (1, 1))
            .expect("the exchange does not pend")
            .expect("a 200 with the field");
        assert_eq!(material.len(), VALUE.len());
        drop(material);
    }

    assert!(
        !SAW_TOKEN.load(Ordering::SeqCst),
        "a freed block still held the token"
    );
    assert!(
        !SAW_VALUE.load(Ordering::SeqCst),
        "a freed block still held the secret value"
    );
}
