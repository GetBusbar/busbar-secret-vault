// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:
//! plugins test themselves against busbar). busbar's suite, at the commit this repo pins
//! (`.busbar-ref`), drives the Vault secret two ways through the one loader: LINKED (the logic
//! crate's `door`) and DROPPED IN (this crate's built cdylib), over the secret kind's script with
//! the inputs in `conformance.json`; every step's first-invocation crossings exactly at the
//! script's pin, the two folds equal, and the suite's RED arms kept. `plugin-ci.yml` runs it under
//! `--release`.
//!
//! THE HOST (ARCHITECT Q-P4-9): the plugin's `http` need is served by busbar's own connector,
//! composed as the root composes it ([`conformance_host`], rendered by the fleet template), and
//! every read reaches a REAL local HTTPS Vault stand-in (the suite's far end, its certificate
//! chained to the suite's test anchors, which only the host trusts): the `addr` in
//! `conformance.json`'s settings. The token is the Statement's secret reference, lent by the host
//! at `open` (the suite's test material).

#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The token the far end accepts (`conformance.json`'s `settings.token`).
const TOKEN: &str = "s.conformance-token";

/// The far end's answer: Vault's KV v2 read API, once a request head is whole. `kv/data/conf`
/// holds `api_key`; any other path is a 404; a request without the token is a 403.
fn vault(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]);
    let path = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or_default();
    let token = head.lines().any(|l| {
        l.split_once(':').is_some_and(|(n, v)| {
            n.trim().eq_ignore_ascii_case("x-vault-token") && v.trim() == TOKEN
        })
    });
    let (status, body) = if !token {
        (
            "403 Forbidden",
            r#"{"errors":["permission denied"]}"#.to_owned(),
        )
    } else if path == "/v1/kv/data/conf" {
        (
            "200 OK",
            r#"{"data":{"data":{"api_key":"sk-conformance"},"metadata":{"version":1}}}"#.to_owned(),
        )
    } else {
        ("404 Not Found", r#"{"errors":[]}"#.to_owned())
    };
    Some(
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
}

/// The host the suite binds the plugin over, with the far end its settings name already listening.
fn host(
    wake: std::sync::Arc<dyn Fn(u64) + Send + Sync>,
    anchors: Option<&str>,
) -> std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> {
    conformance_host::far_end(vault);
    conformance_host::host(wake, anchors)
}

busbar_plugin_loader::conformance_suite! {
    door: busbar_secret_vault::door::door,
    cdylib: "busbar_secret_vault_plugin",
    inputs: include_str!("conformance.json"),
    host: host,
    tls: conformance_host::anchors(),
}
