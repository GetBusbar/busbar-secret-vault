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
//! Fail-closed and specific: a 404 (no secret at that path), a 403 (bad token / missing
//! Vault policy) and a 5xx (Vault itself unhealthy) are distinct, human-readable errors, each tagged
//! with its `abi::secret::ERROR_KIND_*`. No refusal carries the token, the material or any text of
//! Vault's reply (its body, or the names of the fields it holds); an empty field is refused, never
//! resolved empty.

#![forbid(unsafe_code)]

use busbar_contract::secret::{SecretModuleError, SecretResult};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub mod door;

/// The plugin's name: the Statement's and the manifest's. (The `module` alias a reference spells is
/// `vault`.)
pub const NAME: &str = "busbar-secret-vault";

/// The word config names this source by: its module alias, spelled here so a linked build answers
/// it as the dropped-in one does (a linked row takes no manifest alias).
pub const WORD: &str = "vault";

/// Upper bound on a Vault KV v2 response body: generous headroom over a handful of short fields,
/// while bounding the allocation against a hostile or misbehaving endpoint.
pub const MAX_VAULT_RESPONSE_BYTES: usize = 1024 * 1024;

/// The settings key whose value is the token's secret reference (the Statement's `secret_refs`).
pub const TOKEN_KEY: &str = "token";

/// Default HTTP timeout (connect + total), in seconds.
fn default_timeout_secs() -> u64 {
    10
}

/// The open-time settings — the `secrets.<module>.settings` map. `token` is its
/// secret reference as written (the material arrives through `open`'s secrets, never here). Its
/// `Debug` prints `addr` without userinfo and never the token reference (which may be a literal).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// The Vault server address, e.g. `https://vault.internal:8200`. A trailing slash is tolerated.
    pub addr: String,
    /// The token's secret reference, as the operator wrote it (required).
    pub token: serde_json::Value,
    /// An ADDITIONAL trusted root CA certificate (PEM), layered on top of the public root store.
    /// Never disables certificate validation, only widens the trusted-root set. Carried to the
    /// host as the need's `trust_from`.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// HTTP timeout (connect + total), in seconds. Default 10. The host bounds every resolve by its
    /// 30 s call deadline, so a larger value cannot extend it.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
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

/// Parse the open-time settings bytes: an empty (or whitespace-only)
/// config and a malformed one are refused, naming the plugin. Then each value is judged, so
/// `validate`, `open` and `refresh` refuse what could never serve, naming the key (the texts
/// this crate words never quote a value; a JSON type error from `serde_json` can quote the
/// offending, non-secret value): an `addr` that is not an `http://` or `https://` URL naming a host (or that
/// carries a query or fragment, which the request URL cannot carry), a `ca_cert_pem` holding no PEM
/// certificate, and a `timeout_secs` of 0.
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
    let cfg: VaultConfig = serde_json::from_str(text)
        .map_err(|e| format!("invalid hashicorp-vault plugin config: {e}"))?;
    if !addr_is_a_server_url(&cfg.addr) {
        return Err(
            "invalid hashicorp-vault plugin config: `addr` must be an http:// or \
                    https:// URL naming the Vault server (e.g. https://vault.internal:8200), with \
                    no query or fragment"
                .to_string(),
        );
    }
    if let Some(pem) = &cfg.ca_cert_pem {
        check_ca_cert_pem(pem)?;
    }
    if cfg.timeout_secs == 0 {
        return Err(
            "invalid hashicorp-vault plugin config: `timeout_secs` must be at least 1".to_string(),
        );
    }
    Ok(cfg)
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
            break;
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
    let symbols: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if symbols.is_empty() || !symbols.len().is_multiple_of(4) {
        return None;
    }
    let pad = symbols.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    let data = &symbols[..symbols.len() - pad];
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
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

/// Whether `addr` (its userinfo aside, which is stripped as a credential) is an absolute `http` or
/// `https` URL with a host and no query or fragment: the base every request URL is built on.
fn addr_is_a_server_url(addr: &str) -> bool {
    let addr = without_userinfo(addr.trim_end_matches('/'));
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
/// and a setting other than `path` and `field` are refused too.
///
/// # Errors
/// [`SecretErrorKind::Invalid`](busbar_contract::secret::SecretErrorKind::Invalid), naming what is missing.
pub fn parse_reference(
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

    // Explicit `field` wins over any `#` embedded in `path`.
    if let Some(field) = settings.get("field") {
        let field = field.as_str().ok_or_else(|| {
            SecretModuleError::invalid("`field` in secret reference settings must be a string")
        })?;
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

/// ONE framed http request, as the plugin hands it to the host's exchange. The token rides as a
/// head field; `Debug` never prints field values. The fields are clones of the client's token (`Arc`),
/// so the token is wiped when the client (and every request still holding it) drops, not when one
/// request does.
pub struct Request {
    /// The method (`GET`).
    pub method: &'static str,
    /// The display form of the target URL, `{addr}/v1/{path}` with any `addr` userinfo removed: the
    /// URL every refusal text prints. Carries no secret.
    pub url: String,
    /// The framed request's target: the path and query the host sends to the need's pinned target
    /// (`addr`'s own path prefix included). Carries no secret.
    pub target: String,
    /// The head fields: `X-Vault-Token`.
    pub fields: Vec<(&'static str, Arc<Zeroizing<Vec<u8>>>)>,
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
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The body, at most the request's `body_cap` bytes.
    pub body: Vec<u8>,
    /// The body's full length (the short-buffer rule's `needed`); over `body_cap` = too big.
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

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// What an exchange answered for one call.
#[derive(Debug)]
pub enum Exchanged {
    /// Not ready: the host fires the op's wake when it is, and the op is re-invoked.
    Pending,
    /// The response, or the transport's failure text (never secret material).
    Done(Result<Response, String>),
}

/// The host's framed one-shot http exchange, as the plugin sees it: the seam
/// [`door::HostExchange`] implements in production and tests stand in for. Re-serving a stored
/// result to a re-invoked op is the SDK `Op`'s job (it holds the parked exchange on the op's
/// ticket), not this trait's.
pub trait Exchange {
    /// Run (or collect) the exchange.
    fn exchange(&self, request: &Request) -> Exchanged;
}

/// The Vault client: the resolved `addr`, the token material and the transport settings, built
/// once at `open` (and at `refresh`) and reused for every `resolve`.
pub struct VaultClient {
    addr: String,
    token: Arc<Zeroizing<Vec<u8>>>,
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

impl VaultClient {
    /// The client for `cfg`, with the token material the kernel resolved.
    #[must_use]
    pub fn new(cfg: &VaultConfig, token: &[u8]) -> Self {
        Self {
            addr: without_userinfo(cfg.addr.trim_end_matches('/')),
            token: Arc::new(Zeroizing::new(token.to_vec())),
            timeout_secs: cfg.timeout_secs,
            ca_cert_pem: cfg.ca_cert_pem.clone(),
        }
    }

    /// The URL a read of `vault_path` goes to.
    #[must_use]
    pub fn url(&self, vault_path: &str) -> String {
        format!("{}/v1/{}", self.addr, vault_path.trim_start_matches('/'))
    }

    /// The one request a read of `vault_path` sends. Its `target` is the path and query of
    /// `{addr}/v1/{path}` with the bytes a URI cannot hold percent-encoded; it is never a fallback.
    ///
    /// # Errors
    /// [`SecretErrorKind::Unavailable`](busbar_contract::secret::SecretErrorKind::Unavailable): the request URL is not a valid URL.
    pub fn request(&self, vault_path: &str) -> SecretResult<Request> {
        let url = self.url(vault_path);
        let encoded = encode_path(vault_path.trim_start_matches('/'));
        let target = normalise_url_path(&format!("{}/v1/{encoded}", self.addr))
            .parse::<http::Uri>()
            .map_err(|e| e.to_string())
            .and_then(|u| {
                u.path_and_query()
                    .map(|p| p.as_str().to_owned())
                    .ok_or_else(|| "no path".to_owned())
            })
            .map_err(|cause| {
                SecretModuleError::unavailable(format!(
                    "request to Vault ({url}) failed: the request URL is not a valid URL: {cause}"
                ))
            })?;
        Ok(Request {
            method: "GET",
            url,
            target,
            fields: vec![("X-Vault-Token", Arc::clone(&self.token))],
            timeout_ms: self.timeout_secs.saturating_mul(1000),
            trust_pem: self.ca_cert_pem.clone(),
            // One byte past the cap tells "at the cap" from "over it" even if the host reports no
            // full length.
            body_cap: MAX_VAULT_RESPONSE_BYTES + 1,
        })
    }

    /// Resolve `settings` (a reference) through `exchange`: `None` while the exchange is pending.
    pub fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        exchange: &dyn Exchange,
    ) -> Option<SecretResult<Vec<u8>>> {
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

/// `path` as a request target: every byte a URI cannot hold (C0 controls, space, `"`, `#`, `<`, `>`,
/// a backtick, `{`, `}`, DEL and anything >= 0x80) written `%XX`; the rest, `?` (which keeps starting
/// the query) and `%` included, unchanged. A `#` in `path` is therefore data, never a
/// fragment.
fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        if b <= 0x20 || b >= 0x7F || matches!(b, b'"' | b'#' | b'<' | b'>' | b'`' | b'{' | b'}') {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

/// `url` as the `url` crate (WHATWG, special scheme) writes its path, which is how 1.5.5 built the
/// request URL from `{addr}/v1/{path}`: `\` is `/`, a `.` segment (or `%2e`, any case) is dropped,
/// a `..` segment (`.%2e`, `%2e.`, `%2e%2e`) removes the segment before it and never climbs above
/// the root, and a trailing `.`/`..` leaves a trailing `/`. The `addr` prefix and `/v1` are
/// segments like any other, so a leading `..` in the operator's path pops them. The query is left
/// alone.
fn normalise_url_path(url: &str) -> String {
    let path_start = url
        .find("://")
        .and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j));
    let Some(start) = path_start else {
        return url.to_string();
    };
    let (origin, rest) = url.split_at(start);
    let (path, query) = match rest.find('?') {
        Some(q) => rest.split_at(q),
        None => (rest, ""),
    };
    let path = path.replace('\\', "/");
    let is_dots = |seg: &str, n: usize| {
        let lower = seg.to_ascii_lowercase();
        let dots = lower.replace("%2e", ".");
        dots == ".".repeat(n)
    };
    let mut segments: Vec<&str> = Vec::new();
    let all: Vec<&str> = path[1..].split('/').collect();
    for (i, seg) in all.iter().enumerate() {
        let last = i + 1 == all.len();
        if is_dots(seg, 2) {
            segments.pop();
            if last {
                segments.push("");
            }
        } else if is_dots(seg, 1) {
            if last {
                segments.push("");
            }
        } else {
            segments.push(seg);
        }
    }
    format!("{origin}/{}{query}", segments.join("/"))
}

/// `http`'s status rendering (`"404 Not Found"`).
fn status_text(status: u16) -> String {
    match http::StatusCode::from_u16(status) {
        Ok(s) => s.to_string(),
        Err(_) => format!("{status} <unknown status code>"),
    }
}

/// Judge one exchange's outcome for a read of `field` at `vault_path` from `url`, in this order:
/// transport failure, 404, 403, 5xx, the body cap, any other non-2xx, then the KV v2 shape and the
/// field.
///
/// A transport failure's text is `error sending request for url (..)` and the host's own cause
/// follows it (`: {cause}`), so a refused need, an unarmed host or an oversize reply is explained;
/// an empty cause leaves the bare text.
///
/// The copies of the material this holds are wiped when released: the response body (taken into a
/// `Zeroizing` buffer), the parsed JSON tree (every string value, on every return path) and the
/// rendering of a non-string value; the selected string is moved out of the tree, not cloned.
/// Residual (safe code cannot reach either): `serde_json`'s private scratch buffer for strings
/// that contain JSON escapes, and the strings it had built when a body fails to parse partway.
///
/// # Errors
/// The classified refusal; its text never carries the token or the material.
pub fn judge(
    vault_path: &str,
    field: &str,
    url: &str,
    result: Result<Response, String>,
) -> SecretResult<Vec<u8>> {
    let mut resp = result.map_err(|cause| {
        let cause = cause.trim();
        let tail = if cause.is_empty() {
            String::new()
        } else {
            format!(": {cause}")
        };
        SecretModuleError::unavailable(format!(
            "request to Vault ({url}) failed: error sending request for url ({url}){tail}"
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
    let body = Zeroizing::new(std::mem::take(&mut resp.body));

    // No text of the reply is quoted: a body is Vault's, and may carry what it guards.
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

    let mut tree = Wiped(serde_json::from_slice(&body).map_err(|e| {
        SecretModuleError::internal(format!(
            "Vault response for path {vault_path:?} is not valid JSON: {e}"
        ))
    })?);
    let data = tree
        .0
        .get_mut("data")
        .and_then(|d| d.get_mut("data"))
        .and_then(|d| d.as_object_mut())
        .ok_or_else(|| {
            SecretModuleError::invalid(format!(
                "Vault response for path {vault_path:?} has no `data.data` object (not a KV v2 \
                 read? check the path includes the `data/` segment, e.g. \"mount/data/name\")"
            ))
        })?;

    let Some(value) = data.get_mut(field) else {
        return Err(SecretModuleError::not_found(format!(
            "Vault secret at path {vault_path:?} has no field {field:?}"
        )));
    };

    match value {
        serde_json::Value::String(s) if s.is_empty() => Err(SecretModuleError::invalid(format!(
            "Vault secret at path {vault_path:?} field {field:?} is EMPTY; a secret must be \
             non-empty (fail-closed)"
        ))),
        serde_json::Value::String(s) => Ok(std::mem::take(s).into_bytes()),
        other => Ok(render(other)),
    }
}

/// A parsed response whose string values are zeroized when it is dropped, on every return path.
struct Wiped(serde_json::Value);

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Zeroize every string value under `v` (objects' values, arrays recursively); keys are field
/// names and are left alone.
fn wipe(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
        serde_json::Value::Object(map) => map.iter_mut().for_each(|(_, x)| wipe(x)),
        _ => {}
    }
}

/// `v`'s JSON text in a buffer of exactly its length, so no growth frees a partial copy.
fn render(v: &serde_json::Value) -> Vec<u8> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // Serializing a `Value` to a writer cannot fail (its keys are strings).
    let _ = serde_json::to_writer(&mut count, v);
    let mut out = Vec::with_capacity(count.0);
    let _ = serde_json::to_writer(&mut out, v);
    out
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
