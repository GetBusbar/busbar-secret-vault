// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Vault secret module as a droppable busbar plugin** — a `cdylib` that exports the secret C
//! ABI (`busbar_contract::abi::cold::kind::SECRET`). Build it, drop the resulting `.so`/`.dll`/`.dylib` into
//! the engine's plugins folder, give it a module NAME under `secrets:` (its open-time config — the
//! Vault address + token), and reference it from any secret field: `{ module: <alias>, settings: {
//! path: "kv/data/openai#api_key" } }`.
//!
//! All the Vault logic (the KV v2 HTTP client, field addressing, error classification) lives in the
//! `busbar-secret-vault` `lib` crate (usable statically too). Here we only adapt the engine's JSON
//! open-time config into a `VaultConfig` and hand the trait object to the SDK, which emits the
//! extern-C symbols the loader resolves — mirroring `busbar-auth-oidc-plugin`'s `open()` exactly.

use busbar_contract::secret::SecretModule;
use busbar_secret_vault::{VaultConfig, VaultSecretModule};

/// Construct a Vault secret module from the JSON config the engine passes through `open` — the
/// `secrets.<module>.settings` map. Shape:
///
/// ```json
/// {
///   "addr": "https://vault.internal:8200",
///   "token": "s.xxxxxxxx",
///   "ca_cert_pem": null,
///   "timeout_secs": 10
/// }
/// ```
///
/// `addr` and `token` are required; `ca_cert_pem` and `timeout_secs` are optional. An empty config is
/// rejected: a Vault module with no address or token can never resolve anything, so failing at
/// `open()` (a boot-time error naming the reference) is strictly better than deferring the same
/// failure to every `resolve()` call.
fn open(cfg: &str) -> Result<Box<dyn SecretModule>, String> {
    let cfg: VaultConfig = if cfg.trim().is_empty() {
        return Err(
            "hashicorp-vault plugin requires config (addr, token); none provided".to_string(),
        );
    } else {
        serde_json::from_str(cfg)
            .map_err(|e| format!("invalid hashicorp-vault plugin config: {e}"))?
    };
    Ok(Box::new(VaultSecretModule::new(&cfg)?))
}

busbar_contract::export_secret_plugin!(open);

#[cfg(test)]
mod tests;
