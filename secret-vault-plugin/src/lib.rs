// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Vault secret module as a droppable `kind: secret` plugin: the logic crate re-exported whole,
//! with its SDK door exported for the host loader.

#![deny(unsafe_code)]

pub use busbar_secret_vault::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro exports
/// `busbar_plugin_door` for the host loader.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_secret_vault::door::door);
}
