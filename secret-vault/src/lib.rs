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
//! prepend a mount or a `data/` segment to the operator's `path`. The request URL is parsed as
//! 1.5.5's `url` crate parsed it: `\` becomes `/`, `.` segments are dropped, `..` pops the segment
//! before it, tabs and newlines are removed, and a `#` starts the URL fragment, which is never sent.
//!
//! A reference names the field to extract in one of two ways, on the per-reference `settings` map:
//!
//! - `{ "path": "kv/data/openai#api_key" }` — the `#field` suffix; `path` is split on the LAST `#`.
//! - `{ "path": "kv/data/openai", "field": "api_key" }` — two keys. When both are given, `field`
//!   wins (see [`parse_reference`]).
//!
//! ## Sans-IO
//!
//! The plugin never opens a socket, dials or does TLS. [`VaultClient`] builds the
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
//! Fail-closed and specific: a 404 (no secret at that path), a 401/403 (bad token / missing
//! Vault policy) and a 5xx (Vault itself unhealthy) are distinct, human-readable errors, each tagged
//! with its `abi::secret::ERROR_KIND_*`. No refusal carries the token, the material or any text of
//! Vault's reply (its body, or the names of the fields it holds); an empty field is refused, never
//! resolved empty.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::cred::{self, Cred, Held, SelectedJson, SettingsValue};
use busbar_contract::secret::{SecretModuleError, SecretResult};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub(crate) mod door;
mod migrate;

/// The plugin's name: the Statement's and the manifest's. (The `module` alias a reference spells is
/// [`WORD`].)
pub const NAME: &str = "busbar-secret-vault";

/// The word config names this source by: its module alias, spelled here so a linked build answers
/// it as the dropped-in one does (a linked row takes no manifest alias).
pub const WORD: &str = "vault";

/// Upper bound on a Vault KV v2 response body: generous headroom over a handful of short fields,
/// while bounding the allocation against a hostile or misbehaving endpoint. A reply under it is
/// read without building a tree of its siblings, so it cannot grow far past this in memory.
pub(crate) const MAX_VAULT_RESPONSE_BYTES: usize = 1024 * 1024;

/// The settings key whose value is the token's secret reference (the Statement's `secret_refs`).
pub(crate) const TOKEN_KEY: &str = "token";

/// Default HTTP timeout (connect + total), in seconds.
fn default_timeout_secs() -> u64 {
    10
}

/// The open-time settings — the `secrets.<module>.settings` map. `token` is its secret reference
/// as written (the material arrives through `open`'s secrets, never here). Its `Debug` prints
/// `addr` without userinfo and never the token reference (which may be a literal). Dropping it
/// (or a clone) wipes every string it holds.
#[derive(Clone)]
pub(crate) struct VaultConfig {
    /// The Vault server address, e.g. `https://vault.internal:8200`. A trailing slash is tolerated.
    pub addr: String,
    /// The token's secret reference, as the operator wrote it (required).
    _token: SettingsValue,
    /// An ADDITIONAL trusted root CA certificate (PEM), layered on top of the public root store.
    /// Never disables certificate validation, only widens the trusted-root set. Carried to the
    /// host as the need's `trust_from`.
    pub ca_cert_pem: Option<String>,
    /// HTTP timeout (connect + total), in seconds. Default 10. The host bounds every resolve by its
    /// 30 s call deadline, so a larger value cannot extend it.
    pub timeout_secs: u64,
}

impl Drop for VaultConfig {
    fn drop(&mut self) {
        self.addr.zeroize();
        self.ca_cert_pem.zeroize();
    }
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("addr", &without_userinfo(&self.addr))
            .field("token", &"<redacted>")
            .field("ca_cert_pem", &self.ca_cert_pem.is_some())
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

/// Parse the open-time settings bytes: an empty (or whitespace-only) config and a malformed one
/// are refused, naming the plugin, with the guarded parser's current diagnostic. Then
/// each value is judged, so `validate`, `open` and `refresh` refuse what could never serve, naming
/// the key (the texts this crate words never quote a value; parser errors expose only their class and position): an `addr` that is not an `http://` or `https://` URL naming a host
/// (or that carries a query or fragment, which the request URL cannot carry), a `ca_cert_pem`
/// holding no well-formed PEM certificate, and a `timeout_secs` of 0.
///
/// # Errors
/// The operator-facing refusal text.
pub(crate) fn parse_config(settings: &[u8]) -> Result<VaultConfig, String> {
    let text = std::str::from_utf8(settings)
        .map_err(|e| format!("invalid hashicorp-vault plugin config: {e}"))?;
    if text.trim().is_empty() {
        return Err(
            "hashicorp-vault plugin requires config (addr, token); none provided".to_string(),
        );
    }
    let mut tree = cred::settings_document(settings)
        .map_err(|e| format!("invalid hashicorp-vault plugin config: {e}"))?;
    let invalid = |why: &str| format!("invalid hashicorp-vault plugin config: {why}");
    let object = tree
        .as_object()
        .ok_or_else(|| invalid("expected struct VaultConfig"))?;
    const FIELDS: &[&str] = &["addr", "token", "ca_cert_pem", "timeout_secs"];
    if let Some(unknown) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        return Err(invalid(&format!("unknown configuration field `{unknown}`")));
    }
    for name in ["addr", "token"] {
        if !object.contains_key(name) {
            return Err(invalid(&format!("missing field `{name}`")));
        }
    }
    if !tree["addr"].is_string() {
        return Err(invalid("`addr` must be a string"));
    }
    if tree
        .get("ca_cert_pem")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return Err(invalid("`ca_cert_pem` must be a string or null"));
    }
    if tree
        .get("timeout_secs")
        .is_some_and(|v| v.as_u64().is_none())
    {
        return Err(invalid("`timeout_secs` must be a u64"));
    }
    if !addr_is_a_server_url(tree["addr"].as_str().unwrap_or_default()) {
        return Err(
            "invalid hashicorp-vault plugin config: `addr` must be an http:// or \
                    https:// URL naming the Vault server (e.g. https://vault.internal:8200), with \
                    no query or fragment"
                .to_string(),
        );
    }
    if let Some(pem) = tree.get("ca_cert_pem").and_then(serde_json::Value::as_str) {
        check_ca_cert_pem(pem)?;
    }
    let timeout_secs = tree
        .get("timeout_secs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(default_timeout_secs);
    if timeout_secs == 0 {
        return Err(
            "invalid hashicorp-vault plugin config: `timeout_secs` must be at least 1".to_string(),
        );
    }
    Ok(VaultConfig {
        addr: tree
            .take("addr")
            .and_then(SettingsValue::into_string)
            .unwrap_or_default(),
        _token: tree.take(TOKEN_KEY).expect("validated required token"),
        ca_cert_pem: tree
            .take("ca_cert_pem")
            .and_then(SettingsValue::into_string),
        timeout_secs,
    })
}

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Judge a `ca_cert_pem`: it must hold a PEM certificate, and every CERTIFICATE block must decode
/// (1.5.5 refused what `reqwest::Certificate::from_pem` could not read, and the host does not judge
/// a trust anchor at open): its body is valid base64 and its DER is one SEQUENCE of exactly the
/// stated length.
fn check_ca_cert_pem(pem: &str) -> Result<(), String> {
    let no_cert = || {
        "invalid hashicorp-vault plugin config: `ca_cert_pem` holds no PEM certificate \
         (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)"
            .to_string()
    };
    let mut rest = pem;
    let mut n = 0usize;
    while let Some(b) = rest.find(PEM_BEGIN) {
        let after = &rest[b + PEM_BEGIN.len()..];
        let Some(e) = after.find(PEM_END) else {
            return Err(format!(
                "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate {} has no \
                 {PEM_END} line",
                n + 1
            ));
        };
        n += 1;
        let refuse = |why: &str| {
            format!(
                "invalid hashicorp-vault plugin config: invalid ca_cert_pem: certificate {n} {why}"
            )
        };
        let der = decode_base64(&after[..e]).ok_or_else(|| refuse("is not valid base64"))?;
        if !is_der_sequence(&der) {
            return Err(refuse(
                "is not DER (it does not start with a SEQUENCE of the stated length)",
            ));
        }
        rest = &after[e + PEM_END.len()..];
    }
    if n == 0 {
        return Err(no_cert());
    }
    Ok(())
}

/// Strict standard-alphabet base64 (whitespace ignored): padding only at the end and only as needed,
/// no stray bytes, no non-zero trailing bits. `None` when it is not, or decodes to nothing.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let symbols: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(symbols)
        .ok()
        .filter(|bytes| !bytes.is_empty())
}

/// Whether `der` is exactly one DER SEQUENCE: tag 0x30, a definite length (short form, or long form
/// of at most four bytes) that accounts for every byte after the header.
fn is_der_sequence(der: &[u8]) -> bool {
    let [0x30, first, tail @ ..] = der else {
        return false;
    };
    if *first < 0x80 {
        return tail.len() == usize::from(*first);
    }
    let n = usize::from(*first & 0x7F);
    if n == 0 || n > 4 || tail.len() < n {
        return false;
    }
    let len = tail[..n]
        .iter()
        .fold(0usize, |l, &b| (l << 8) | usize::from(b));
    tail.len() - n == len
}

/// `addr` as every request is built on it: its trailing slashes and any userinfo removed.
fn base_addr(addr: &str) -> String {
    without_userinfo(addr.trim_end_matches('/'))
}

/// Whether `addr` (its userinfo aside, which is stripped as a credential) is an absolute `http` or
/// `https` URL with a host and no query or fragment: the base every request URL is built on.
fn addr_is_a_server_url(addr: &str) -> bool {
    let addr = base_addr(addr);
    if addr.contains(['?', '#']) {
        return false;
    }
    match addr.parse::<http::Uri>() {
        Ok(u) => {
            matches!(u.scheme_str(), Some("http" | "https"))
                && u.host().is_some_and(|h| !h.is_empty())
        }
        Err(_) => false,
    }
}

/// Split a per-reference `settings` map into `(vault_path, field)`. Fail-closed: a missing `path`,
/// or a `path` with no `#field` suffix and no separate `field` key, is an `Err` naming exactly
/// what's missing, and a `field` that is not a string is refused rather than ignored. A blank `path`
/// and a setting other than `path` and `field` are refused too. With a `field` key, `path` is kept
/// whole; a `#` left in it starts the request URL's fragment, as in 1.5.5 (see [`VaultClient::request`]).
///
/// # Errors
/// [`SecretErrorKind::Invalid`](busbar_contract::secret::SecretErrorKind::Invalid), naming what is missing.
pub(crate) fn parse_reference(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<(String, String)> {
    let path = settings
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SecretModuleError::invalid("missing or non-string `path` in secret reference settings")
        })?;
    if path.trim().is_empty() {
        return Err(SecretModuleError::invalid(
            "`path` in secret reference settings must not be blank",
        ));
    }
    if let Some(other) = settings
        .keys()
        .find(|k| !matches!(k.as_str(), "path" | "field"))
    {
        return Err(SecretModuleError::invalid(format!(
            "vault secret reference does not take settings.{other}; it names only settings.path \
             and settings.field (fail-closed)"
        )));
    }

    if let Some(field) = settings.get("field") {
        let field = field.as_str().ok_or_else(|| {
            SecretModuleError::invalid("`field` in secret reference settings must be a string")
        })?;
        if field.trim().is_empty() {
            return Err(SecretModuleError::invalid(
                "`field` in secret reference settings must not be blank",
            ));
        }
        return Ok((path.to_string(), field.to_string()));
    }

    match path.rsplit_once('#') {
        Some((p, f)) if p.trim().is_empty() && !f.is_empty() => Err(SecretModuleError::invalid(
            "`path` in secret reference settings must not be blank",
        )),
        Some((p, f)) if !p.is_empty() && !f.trim().is_empty() => Ok((p.to_string(), f.to_string())),
        _ => Err(SecretModuleError::invalid(format!(
            "vault secret reference must name a field to extract: either add a `field` key, or \
             suffix `path` with `#<field>` (e.g. \"kv/data/openai#api_key\"); got path {path:?}"
        ))),
    }
}

/// ONE framed http request, as the plugin hands it to the host's exchange. The token rides as a
/// sealed head field; `Debug` never prints field values. Requests clone the opaque credential,
/// which wipes when its last client or request owner drops.
pub(crate) struct Request {
    /// The method (`GET`).
    pub method: &'static str,
    /// The display form of the target URL, `{addr}/v1/{path}` with any `addr` userinfo removed: the
    /// URL every refusal text prints, as 1.5.5's did. Carries no secret.
    pub url: String,
    /// The framed request's target: the path and query the host sends to the need's pinned target
    /// (`addr`'s own path prefix included), as the `url` crate parsed [`Request::url`] in 1.5.5.
    /// Carries no secret.
    pub target: String,
    /// The head fields: `X-Vault-Token`.
    pub fields: Vec<(&'static str, Cred)>,
    /// The connect + total timeout, in milliseconds.
    pub timeout_ms: u64,
    /// The extra trusted root (PEM) the need's `trust_from` names; `None` = the public roots.
    pub trust_pem: Option<Arc<Zeroizing<String>>>,
    /// The body cap supplied to the bounded host exchange; one byte over the accepted material
    /// limit distinguishes a complete at-limit response from an oversized response.
    pub body_cap: usize,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("target", &self.target)
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

/// ONE framed http response, as the exchange answers it. Dropping it zeroizes the body, and `Debug`
/// never prints it (it may hold the material).
#[derive(PartialEq, Eq)]
pub(crate) struct Response {
    /// The status code.
    pub status: u16,
    /// The body, at most the request's `body_cap` bytes.
    pub body: Held<Vec<u8>>,
    /// The body's length, or a lower bound above `body_cap` when its streaming read stopped at
    /// that cap; over `body_cap` = too big.
    pub body_len: usize,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("body_len", &self.body_len)
            .finish()
    }
}

/// What an exchange answered for one call.
#[derive(Debug)]
pub(crate) enum Exchanged {
    /// Not ready: the host fires the op's wake when it is, and the op is re-invoked.
    Pending,
    /// The response, or the host's [`ConnFailure`] class (its text never carries secret material):
    /// `judge` maps the class to the refusal's kind.
    Done(Result<Response, ConnFailure>),
}

/// The host's framed one-shot http exchange, as the plugin sees it: the seam
/// [`door::HostExchange`] implements in production and tests stand in for. Re-serving a stored
/// result to a re-invoked op is the SDK `Op`'s job (it holds the parked exchange on the op's
/// ticket), not this trait's.
pub(crate) trait Exchange {
    /// Run (or collect) the exchange.
    fn exchange(&self, request: &Request) -> Exchanged;
}

/// The Vault client: the resolved `addr`, the token material and the transport settings, built
/// once at `open` (and at `refresh`) and reused for every `resolve`.
pub(crate) struct VaultClient {
    addr: String,
    token: Cred,
    timeout_secs: u64,
    ca_cert_pem: Option<Arc<Zeroizing<String>>>,
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

impl VaultClient {
    /// The client for `cfg`, with the token material the kernel resolved.
    #[must_use]
    pub fn new(cfg: &VaultConfig, token: &[u8]) -> Self {
        Self {
            addr: base_addr(&cfg.addr),
            token: Cred::captured(Zeroizing::new(token.to_vec())),
            timeout_secs: cfg.timeout_secs,
            ca_cert_pem: cfg
                .ca_cert_pem
                .as_ref()
                .map(|pem| Arc::new(Zeroizing::new(pem.clone()))),
        }
    }

    /// The URL a read of `vault_path` goes to.
    #[must_use]
    pub fn url(&self, vault_path: &str) -> String {
        format!("{}/v1/{}", self.addr, vault_path.trim_start_matches('/'))
    }

    /// The one request a read of `vault_path` sends. Its `target` is the path and query of
    /// `{addr}/v1/{path}` as the `url` crate parses it (using `url::Url`); the fragment a `#`
    /// starts is not sent. It is never a fallback.
    ///
    /// # Errors
    /// [`SecretErrorKind::Internal`](busbar_contract::secret::SecretErrorKind::Internal): the request URL is not a valid URL.
    pub fn request(&self, vault_path: &str) -> SecretResult<Request> {
        let url = self.url(vault_path);
        let target = url::Url::parse(&url)
            .and_then(|parsed| {
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                    return Err(url::ParseError::RelativeUrlWithoutBase);
                }
                Ok(parsed[url::Position::BeforePath..url::Position::AfterQuery].to_owned())
            })
            .map_err(|cause| {
                SecretModuleError::internal(format!(
                    "request to Vault ({url}) failed: the request URL is not a valid URL: {cause}"
                ))
            })?;
        Ok(Request {
            method: "GET",
            url,
            target,
            fields: vec![("X-Vault-Token", self.token.clone())],
            timeout_ms: self.timeout_secs.saturating_mul(1000),
            trust_pem: self.ca_cert_pem.clone(),
            body_cap: MAX_VAULT_RESPONSE_BYTES + 1,
        })
    }

    /// Resolve `settings` (a reference) through `exchange`: `None` while the exchange is pending.
    pub fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        exchange: &dyn Exchange,
    ) -> Option<SecretResult<Held<Vec<u8>>>> {
        let (path, field) = match parse_reference(settings) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        let request = match self.request(&path) {
            Ok(r) => r,
            Err(e) => return Some(Err(e)),
        };
        match exchange.exchange(&request) {
            Exchanged::Pending => None,
            Exchanged::Done(result) => Some(judge(&path, &field, &request.url, result)),
        }
    }
}

/// `addr` with any userinfo removed: the host strips it from the dial target as a credential, so it
/// must never reach a refusal text or `Debug`. The authority is the text after `://` (when a scheme
/// is there, else from the start) up to the first `/`, `?` or `#`; everything up to and including
/// its LAST `@` is dropped.
fn without_userinfo(addr: &str) -> String {
    let start = match addr.find("://") {
        Some(i) if !addr[..i].contains(['/', '?', '#']) => i + 3,
        _ => 0,
    };
    let end = addr[start..]
        .find(['/', '?', '#'])
        .map_or(addr.len(), |i| start + i);
    match addr[start..end].rfind('@') {
        Some(at) => format!("{}{}", &addr[..start], &addr[start + at + 1..]),
        None => addr.to_string(),
    }
}

/// `http`'s status rendering (`"404 Not Found"`).
fn status_text(status: u16) -> String {
    match http::StatusCode::from_u16(status) {
        Ok(s) => s.to_string(),
        Err(_) => format!("{status} <unknown status code>"),
    }
}

/// Judge one exchange's outcome for a read of `field` at `vault_path` from `url`, in this order:
/// transport failure, 404, 401/403, 429, 5xx, the body cap, 3xx (a redirect is never followed), any
/// other non-2xx, then the JSON, the KV v2 shape and the field.
///
/// A transport failure names the configured request URL and the host's cause, so a refused
/// need, an unarmed host or an oversize reply is explained; an empty cause leaves the bare text.
///
/// The reply is read without handing `serde_json` a string's bytes and without building a tree:
/// only `data.data.<field>` is decoded, into a guarded buffer, and every other value is validated
/// in place. A selected string stays in SDK custody as the material; a non-string value is written as its
/// JSON text (what 1.5.5's `serde_json::Value` printed) into an exactly sized buffer. The body
/// and every decoded key and value are wiped on release.
///
/// # Errors
/// The classified refusal; its text never carries the token or the material.
pub(crate) fn judge(
    vault_path: &str,
    field: &str,
    url: &str,
    result: Result<Response, ConnFailure>,
) -> SecretResult<Held<Vec<u8>>> {
    let resp = result.map_err(|failure| {
        let cause = failure.to_string();
        let cause = cause.trim();
        let tail = if cause.is_empty() {
            String::new()
        } else {
            format!(": {cause}")
        };
        let text = format!("request to Vault ({url}) failed{tail}");
        match failure {
            ConnFailure::Failed(_) | ConnFailure::CredentialUnavailable => {
                SecretModuleError::unavailable(text)
            }
            ConnFailure::Refused(_) => SecretModuleError::denied(text),
            ConnFailure::Unarmed | ConnFailure::NoTicket | ConnFailure::Fault => {
                SecretModuleError::internal(text)
            }
        }
    })?;
    let status = resp.status;
    if status == 404 {
        return Err(SecretModuleError::not_found(format!(
            "Vault has no secret at path {vault_path:?} (404 from {url})"
        )));
    }
    if status == 403 || status == 401 {
        return Err(SecretModuleError::denied(format!(
            "Vault denied reading path {vault_path:?} ({} from {url}): check the token is \
             valid and its policy grants read on this path",
            status_text(status)
        )));
    }
    if status == 429 {
        return Err(SecretModuleError::unavailable(format!(
            "Vault rate limited reading path {vault_path:?}: HTTP {} from {url}",
            status_text(status)
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

    if (300..400).contains(&status) {
        return Err(SecretModuleError::internal(format!(
            "Vault returned HTTP {} reading path {vault_path:?} ({url}): a redirect is not \
             followed; set `addr` to the address Vault redirects to (e.g. the active node)",
            status_text(status)
        )));
    }
    if !(200..300).contains(&status) {
        return Err(SecretModuleError::internal(format!(
            "Vault returned HTTP {} reading path {vault_path:?} ({url})",
            status_text(status)
        )));
    }

    let selected = cred::select_json(body, &["data", "data", field]).map_err(|e| {
        SecretModuleError::internal(format!(
            "Vault response for path {vault_path:?} is not valid JSON: {e}"
        ))
    })?;
    match selected {
        SelectedJson::WrongContainer { .. } | SelectedJson::Missing { segment: 0 | 1 } => {
            Err(SecretModuleError::invalid(format!(
                "Vault response for path {vault_path:?} has no `data.data` object (not a KV v2 \
             read? check the path includes the `data/` segment, e.g. \"mount/data/name\")"
            )))
        }
        SelectedJson::Missing { .. } => Err(SecretModuleError::not_found(format!(
            "Vault secret at path {vault_path:?} has no field {field:?}"
        ))),
        SelectedJson::Value(text) if text.is_empty() => Err(SecretModuleError::invalid(format!(
            "Vault secret at path {vault_path:?} field {field:?} is EMPTY; a secret must be \
             non-empty (fail-closed)"
        ))),
        SelectedJson::Value(text) => Ok(text),
        SelectedJson::Null => Err(SecretModuleError::invalid(format!(
            "Vault secret at path {vault_path:?} field {field:?} is null; a secret must be \
             non-empty (fail-closed)"
        ))),
    }
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/wiping_tests.rs"]
mod wiping_tests;

#[cfg(test)]
#[path = "tests/audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
#[path = "tests/custody_support.rs"]
mod custody_support;

/// The validated entry and generated registration descriptor.
pub use door::{door, MACRO_DOOR};
