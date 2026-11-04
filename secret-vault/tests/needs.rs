// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Statement's needs, compared by their string CONTENTS (not lengths). Reading an `AbiStr`

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_secret_vault::door::STATEMENT;

fn text(s: &AbiStr) -> &str {
    if s.is_absent() {
        return "";
    }
    // SAFETY: every string in the Statement is a `&'static str` (`abi_str`), valid for the run.
    unsafe { s.as_str() }.expect("utf-8")
}

#[test]
fn the_needs_name_the_transport_target_and_trust_by_content() {
    // SAFETY: `needs` points at the static `NEEDS` array of `needs_len` entries.
    let needs = unsafe { std::slice::from_raw_parts(STATEMENT.needs, STATEMENT.needs_len) };
    assert_eq!(needs.len(), 2);
    for n in needs {
        assert_eq!(text(&n.transport), "http");
        assert_eq!(text(&n.target_from), "settings.addr");
    }
    assert_eq!(text(&needs[0].trust_from), "", "the public-roots need");
    assert_eq!(text(&needs[1].trust_from), "settings.ca_cert_pem");
}

#[test]
fn the_statement_names_the_plugin_and_its_one_secret_reference_by_content() {
    assert_eq!(text(&STATEMENT.name), "busbar-secret-vault");
    // SAFETY: `secret_refs` points at the static `SECRET_REFS` array of `secret_refs_len` entries.
    let refs =
        unsafe { std::slice::from_raw_parts(STATEMENT.secret_refs, STATEMENT.secret_refs_len) };
    assert_eq!(refs.len(), 1);
    assert_eq!(text(&refs[0]), "token");
}
