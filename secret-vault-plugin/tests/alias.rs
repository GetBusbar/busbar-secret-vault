// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WORD THIS SOURCE ANSWERS TO, as the host reads it: a linked row takes no manifest alias, so
//! the Statement must declare the alias itself.

use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
use busbar_contract::abi::mechanism::rendering::read;
use busbar_plugin_loader::dispatch::LinkedRow;

#[test]
fn the_statement_states_the_module_alias_and_nothing_else() {
    let row = LinkedRow::of(busbar_secret_vault::door::door)
        .expect("the linked door states its Statement");
    let rewrites = read(&row.statement)
        .expect("the Statement rendering reads back")
        .rewrites;
    assert_eq!(
        rewrites,
        vec![(REWRITE_ALIAS, "vault".to_string(), String::new())],
        "one alias, no shorthand: vault has no `{{ vault: X }}` sugar"
    );
}
