// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **HashiCorp Vault** backend for busbar's `kind: secret` plugin family, on the secret kind's
//! memory ABI (`busbar_contract::abi::secret`). This crate is the LOGIC and its door
//! ([`door::door`]); the dropped-in `cdylib` is the sibling `busbar-secret-vault-plugin` crate,
//! which exports the same door as `busbar_plugin_door`.
//!
//! ## What it does
//!
//! Reads one field out of a Vault [KV v2 secrets
//! engine](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) entry over Vault's HTTP API:
//!
//! ```text
//! GET {addr}/v1/{path}          Header: X-Vault-Token: <token>
//! ⇒ { "data": { "data": { "<field>": "...", ... }, "metadata": {...} } }
//! ```
//!
//! `path` is the FULL v1 API path including the KV v2 `data/` segment the engine requires (e.g.
//! `kv/data/openai` for a `kv/` mount holding a secret at `openai`) — this crate does not itself
//! prepend a mount or a `data/` segment; the operator's `path` is used verbatim after `{addr}/v1/`.
//!
//! A reference names the field to extract in one of two ways, on the per-reference `settings` map:
//!
//! - `{ "path": "kv/data/openai#api_key" }` — the `#field` suffix; `path` is split on the LAST `#`.
//! - `{ "path": "kv/data/openai", "field": "api_key" }` — two keys. When both are given, `field`
//!   wins (see [`parse_reference`]).
//!
//! ## Sans-IO
//!
//! The plugin never opens a socket, dials or does TLS (THE DESIGN §5). [`VaultClient`] builds the
//! one request ([`Request`]) and judges the one response ([`Response`]); the bytes travel through
//! an [`Exchange`] — the host's framed one-shot http exchange over this plugin's declared need
//! (`operator-infrastructure`, target from `addr`, extra trusted root from `ca_cert_pem`). An
//! exchange that cannot finish now answers [`Exchanged::Pending`] and the op answers PENDING; the
//! host re-invokes it on the wake and the same exchange answers its stored result.
//!
//! ## Auth
//!
//! Exactly one Vault auth method: a pre-obtained token sent as `X-Vault-Token`. The token is a
//! secret REFERENCE in `secrets.<module>.settings.token`; the kernel resolves it through the
//! bootstrap secret plugins and hands the material to `open` (the Statement's `secret_refs`). The
//! token never appears in an error text, a log line or a URL.
//!
//! ## Errors
//!
//! Fail-closed and specific, as 1.5.5: a 404 (no secret at that path), a 403 (bad token / missing
//! Vault policy) and a 5xx (Vault itself unhealthy) are distinct, human-readable errors, each tagged
//! with its `abi::secret::ERROR_KIND_*`.

#![forbid(unsafe_code)]

use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::secret::{SecretErrorKind, SecretModuleError, SecretResult};
use serde::Deserialize;

pub mod door;

/// The plugin's name (the manifest name) and the `module` alias a reference spells.
pub const NAME: &str = "busbar-secret-vault";

/// Upper bound on a Vault KV v2 response body, as 1.5.5. A KV v2 entry is typically a handful of
/// short fields; this is generous headroom while still bounding the allocation against a hostile
/// or misbehaving Vault endpoint.
pub const MAX_VAULT_RESPONSE_BYTES: usize = 1024 * 1024;

/// The settings key whose value is the token's secret reference (the Statement's `secret_refs`).
pub const TOKEN_KEY: &str = "token";

/// Default HTTP timeout (connect + total), in seconds, as 1.5.5.
fn default_timeout_secs() -> u64 {
    10
}

/// The open-time settings — the `secrets.<module>.settings` map, as 1.5.5 read it. `token` is its
/// secret reference as written (the material arrives through `open`'s secrets, never here).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// The Vault server address, e.g. `https://vault.internal:8200`. A trailing slash is tolerated.
    pub addr: String,
    /// The token's secret reference, as the operator wrote it (required, as 1.5.5).
    pub token: serde_json::Value,
    /// An ADDITIONAL trusted root CA certificate (PEM), layered on top of the public root store.
    /// Never disables certificate validation, only widens the trusted-root set. Carried to the
    /// host as the need's `trust_from`.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// HTTP timeout (connect + total), in seconds. Default 10.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

/// Parse the open-time settings bytes, with 1.5.5's refusal texts: an empty (or whitespace-only)
/// config and a malformed one are refused, naming the plugin.
///
/// # Errors
/// The operator-facing refusal text.
pub fn parse_config(settings: &[u8]) -> Result<VaultConfig, String> {
    let text = std::str::from_utf8(settings)
        .map_err(|e| format!("invalid hashicorp-vault plugin config: {e}"))?;
    if text.trim().is_empty() {
        return Err(
            "hashicorp-vault plugin requires config (addr, token); none provided".to_string(),
        );
    }
    serde_json::from_str(text).map_err(|e| format!("invalid hashicorp-vault plugin config: {e}"))
}

/// Split a per-reference `settings` map into `(vault_path, field)`. Fail-closed: a missing `path`,
/// or a `path` with no `#field` suffix and no separate `field` key, is an `Err` naming exactly
/// what's missing. Texts are 1.5.5's.
///
/// # Errors
/// [`SecretErrorKind::Invalid`], naming what is missing.
pub fn parse_reference(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<(String, String)> {
    let path = settings
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SecretModuleError::invalid("missing or non-string `path` in secret reference settings")
        })?;

    // Explicit `field` wins over any `#` embedded in `path`.
    if let Some(field) = settings.get("field").and_then(|v| v.as_str()) {
        if field.is_empty() {
            return Err(SecretModuleError::invalid(
                "`field` in secret reference settings must not be empty",
            ));
        }
        return Ok((path.to_string(), field.to_string()));
    }

    match path.rsplit_once('#') {
        Some((p, f)) if !p.is_empty() && !f.is_empty() => Ok((p.to_string(), f.to_string())),
        _ => Err(SecretModuleError::invalid(format!(
            "vault secret reference must name a field to extract: either add a `field` key, or \
             suffix `path` with `#<field>` (e.g. \"kv/data/openai#api_key\"); got path {path:?}"
        ))),
    }
}

/// A `resolve`'s settings blob as an object (empty = `{}`).
///
/// # Errors
/// [`SecretErrorKind::Invalid`]: the bytes are not a JSON object.
pub fn settings_of(bytes: &[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        SecretModuleError::invalid(format!("secret settings are not a JSON object: {e}"))
    })
}

/// The `abi::secret::ERROR_KIND_*` code of a [`SecretErrorKind`].
#[must_use]
pub const fn error_kind(kind: SecretErrorKind) -> u32 {
    match kind {
        SecretErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
        SecretErrorKind::Unavailable => ERROR_KIND_UNAVAILABLE,
        SecretErrorKind::Denied => ERROR_KIND_DENIED,
        SecretErrorKind::Invalid => ERROR_KIND_INVALID,
        SecretErrorKind::Internal => ERROR_KIND_INTERNAL,
    }
}

/// ONE framed http request, as the plugin hands it to the host's exchange. The token rides as a
/// head field; `Debug` never prints field values.
pub struct Request {
    /// The method (`GET`).
    pub method: &'static str,
    /// The full target URL, `{addr}/v1/{path}`. Carries no secret.
    pub url: String,
    /// The head fields: `X-Vault-Token`.
    pub fields: Vec<(&'static str, Vec<u8>)>,
    /// The connect + total timeout, in milliseconds.
    pub timeout_ms: u64,
    /// The extra trusted root (PEM) the need's `trust_from` names; `None` = the public roots.
    pub trust_pem: Option<String>,
    /// The body cap: the response body buffer the exchange fills.
    pub body_cap: usize,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "fields",
                &self.fields.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            )
            .field("timeout_ms", &self.timeout_ms)
            .field("trust_pem", &self.trust_pem.is_some())
            .field("body_cap", &self.body_cap)
            .finish()
    }
}

/// ONE framed http response, as the exchange answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The body, at most the request's `body_cap` bytes.
    pub body: Vec<u8>,
    /// The body's full length (the short-buffer rule's `needed`); over `body_cap` = too big.
    pub body_len: usize,
}

/// What an exchange answered for one call.
#[derive(Debug)]
pub enum Exchanged {
    /// Not ready: the host fires the op's wake when it is, and the op is re-invoked.
    Pending,
    /// The response, or the transport's failure text (never secret material).
    Done(Result<Response, String>),
}

/// The host's framed one-shot http exchange, as the plugin sees it. `ticket` names the op: a
/// re-invoked op asking again on the same ticket receives the stored result, never a second
/// request.
pub trait Exchange {
    /// Run (or collect) the exchange for `ticket`.
    fn exchange(&self, ticket: (u32, u32), request: &Request) -> Exchanged;
}

/// The Vault client: the resolved `addr`, the token material and the transport settings, built
/// once at `open` (and at `refresh`) and reused for every `resolve`.
pub struct VaultClient {
    addr: String,
    token: Vec<u8>,
    timeout_secs: u64,
    ca_cert_pem: Option<String>,
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("addr", &self.addr)
            .field("timeout_secs", &self.timeout_secs)
            .field("ca_cert_pem", &self.ca_cert_pem.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for VaultClient {
    fn drop(&mut self) {
        self.token.fill(0);
    }
}

impl VaultClient {
    /// The client for `cfg`, with the token material the kernel resolved.
    #[must_use]
    pub fn new(cfg: &VaultConfig, token: &[u8]) -> Self {
        Self {
            addr: cfg.addr.trim_end_matches('/').to_string(),
            token: token.to_vec(),
            timeout_secs: cfg.timeout_secs,
            ca_cert_pem: cfg.ca_cert_pem.clone(),
        }
    }

    /// The URL a read of `vault_path` goes to.
    #[must_use]
    pub fn url(&self, vault_path: &str) -> String {
        format!("{}/v1/{}", self.addr, vault_path.trim_start_matches('/'))
    }

    /// The one request a read of `vault_path` sends.
    #[must_use]
    pub fn request(&self, vault_path: &str) -> Request {
        Request {
            method: "GET",
            url: self.url(vault_path),
            fields: vec![("X-Vault-Token", self.token.clone())],
            timeout_ms: self.timeout_secs.saturating_mul(1000),
            trust_pem: self.ca_cert_pem.clone(),
            // One byte past the cap tells "at the cap" from "over it" even if the host reports no
            // full length.
            body_cap: MAX_VAULT_RESPONSE_BYTES + 1,
        }
    }

    /// Resolve `settings` (a reference) through `exchange` for the op on `ticket`: `None` while
    /// the exchange is pending.
    pub fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        exchange: &dyn Exchange,
        ticket: (u32, u32),
    ) -> Option<SecretResult<Vec<u8>>> {
        let (path, field) = match parse_reference(settings) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        let request = self.request(&path);
        match exchange.exchange(ticket, &request) {
            Exchanged::Pending => None,
            Exchanged::Done(result) => Some(judge(&path, &field, &request.url, result)),
        }
    }
}

/// `http`'s status rendering (`"404 Not Found"`), the text 1.5.5's client printed.
fn status_text(status: u16) -> String {
    match http::StatusCode::from_u16(status) {
        Ok(s) => s.to_string(),
        Err(_) => format!("{status} <unknown status code>"),
    }
}

/// Judge one exchange's outcome for a read of `field` at `vault_path` from `url`, with 1.5.5's
/// classes and texts, in 1.5.5's order: transport failure, 404, 403, 5xx, the body cap, any other
/// non-2xx, then the KV v2 shape and the field.
///
/// A transport failure reads as 1.5.5 printed every one of them (refused, unresolvable, TLS,
/// timeout alike): its HTTP client's fixed `error sending request for url (..)`, which never carried
/// the cause. The host's own failure text is therefore not part of the refusal.
///
/// # Errors
/// The classified refusal; its text never carries the token or the material.
pub fn judge(
    vault_path: &str,
    field: &str,
    url: &str,
    result: Result<Response, String>,
) -> SecretResult<Vec<u8>> {
    let resp = result.map_err(|_| {
        SecretModuleError::unavailable(format!(
            "request to Vault ({url}) failed: error sending request for url ({url})"
        ))
    })?;
    let status = resp.status;
    if status == 404 {
        return Err(SecretModuleError::not_found(format!(
            "Vault has no secret at path {vault_path:?} (404 from {url})"
        )));
    }
    if status == 403 {
        return Err(SecretModuleError::denied(format!(
            "Vault denied reading path {vault_path:?} (403 from {url}): check the token is \
             valid and its policy grants read on this path"
        )));
    }
    if (500..600).contains(&status) {
        return Err(SecretModuleError::unavailable(format!(
            "Vault server error reading path {vault_path:?}: HTTP {} from {url}",
            status_text(status)
        )));
    }

    let cap = MAX_VAULT_RESPONSE_BYTES;
    if resp.body_len.max(resp.body.len()) > cap {
        return Err(SecretModuleError::unavailable(format!(
            "Vault response body exceeds the {cap}-byte cap (path {vault_path:?}, {url})"
        )));
    }
    let body = resp.body;

    if !(200..300).contains(&status) {
        let excerpt: String = String::from_utf8_lossy(&body).chars().take(300).collect();
        return Err(SecretModuleError::internal(format!(
            "Vault returned HTTP {} reading path {vault_path:?} ({url}): {excerpt}",
            status_text(status)
        )));
    }

    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        SecretModuleError::internal(format!(
            "Vault response for path {vault_path:?} is not valid JSON: {e}"
        ))
    })?;
    let data = v
        .get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.as_object())
        .ok_or_else(|| {
            SecretModuleError::invalid(format!(
                "Vault response for path {vault_path:?} has no `data.data` object (not a KV v2 \
                 read? check the path includes the `data/` segment, e.g. \"mount/data/name\")"
            ))
        })?;

    let value = data.get(field).ok_or_else(|| {
        let available: Vec<&str> = data.keys().map(String::as_str).collect();
        SecretModuleError::not_found(format!(
            "Vault secret at path {vault_path:?} has no field {field:?}; available fields: \
             {available:?}"
        ))
    })?;

    match value {
        serde_json::Value::String(s) => Ok(s.clone().into_bytes()),
        other => Ok(other.to_string().into_bytes()),
    }
}

#[cfg(test)]
mod tests;
