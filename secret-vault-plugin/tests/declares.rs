// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARES DOCUMENT, as the host reads it: the Vault source reaches its server over the
//! `http` transport (one network need) and never touches the disk. The loader's ONE reader of a
//! declares document, at the busbar commit this repo pins, checks `needs` is a list of scheme
//! names and takes it out (the needs belong to the Statement), then reads the rest.

use busbar_plugin_loader::sign::Declares;

const DECLARES: &[u8] = include_bytes!("../../secret-vault/declares.json");

#[test]
fn the_declares_document_reads_and_states_no_disk() {
    let declares = Declares::from_declares_json(DECLARES).expect("the declares document reads");
    assert!(!declares.disk, "the Vault source never reads the disk");
    assert_eq!(
        declares,
        Declares::default(),
        "beyond its network need the Vault source declares nothing"
    );
}

#[test]
fn the_declares_document_states_the_http_need() {
    let doc: serde_json::Value = serde_json::from_slice(DECLARES).expect("the document is JSON");
    assert_eq!(doc["needs"], serde_json::json!(["http"]));
}
