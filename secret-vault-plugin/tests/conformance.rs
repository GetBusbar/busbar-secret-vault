// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE SECRET MODULE, BOTH DOORS, ONE ROW** — the Vault secret module's linked + dropped-in
//! conformance (DECISIONS #2 rule (1): a plugin is compiled in OR dropped in — same contract, same
//! loading path), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The module is held two ways at once: LINKED (this crate's `BUSBAR_COLD_ENTRY`, the boundary
//! `export_secret_plugin!` emits and a busbar build that compiles the module in hands the loader,
//! through `PluginRegistry::link`) and DROPPED IN (this crate's built cdylib, signed first-party
//! under the SAME statement into a temp `plugins/` directory and found by the loader's scan). Each
//! arm is opened by the one `open_secret` against a loopback KV v2 responder and driven through the
//! same script — a field read, a missing field, a missing secret, a denied path, a malformed
//! reference — each a real HTTP round trip by the module's own client, and the two transcripts,
//! with the registry row each door resolves the name to, must be byte-identical. The live Vault
//! dev server is `tests/e2e.rs`.
//!
//! The RED arms are in the same file: the same cdylib opened under a DIFFERENT config (another
//! token) is a different transcript (so the equality is not vacuous), and the same bytes signed as
//! `auth` are refused at the kind handshake, naming both kinds. A missing cdylib PANICS — this test
//! IS the dropped-in door's proof, and never skips.

use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};
use std::io::{BufRead, BufReader, Write};

/// The module's registry name and alias (what a `{ module: vault, settings: {...} }` reference names).
const NAME: &str = "busbar-secret-vault";
const ALIAS: &str = "vault";

/// The token the loopback responder honours.
const TOKEN: &str = "s.conformance";

/// A loopback KV v2 responder: `GET /v1/kv/data/openai` answers the entry to [`TOKEN`], a known
/// `denied` path answers 403, a wrong token answers 403, anything else 404. One request per
/// connection (`Connection: close`). Returns its base address.
fn spawn_kv() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            let _ = reader.read_line(&mut request_line);
            let mut token = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    if k.eq_ignore_ascii_case("x-vault-token") {
                        token = v.trim().to_string();
                    }
                }
            }
            let path = request_line.split_whitespace().nth(1).unwrap_or("");
            let (status, body) = match (token == TOKEN, path) {
                (false, _) | (true, "/v1/kv/data/denied") => {
                    ("403 Forbidden", r#"{"errors":["permission denied"]}"#)
                }
                (true, "/v1/kv/data/openai") => (
                    "200 OK",
                    r#"{"data":{"data":{"api_key":"sk-conformance","org":"acme"},"metadata":{"version":3}}}"#,
                ),
                _ => ("404 Not Found", r#"{"errors":[]}"#),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    addr
}

fn config(addr: &str, token: &str) -> String {
    serde_json::json!({ "addr": addr, "token": token, "timeout_secs": 5 }).to_string()
}

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_secret_vault_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-secret-vault-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both doors make for the module, as `kind`, at the newest payload schema the
/// loader speaks for that kind.
fn statement(kind: &str) -> Manifest {
    Manifest {
        name: NAME.into(),
        alias: ALIAS.into(),
        kind: kind.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: *busbar_plugin_loader::supported_abi(kind)
            .iter()
            .max()
            .expect("a payload schema for the kind"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// THE LINKED DOOR: this crate's boundary, registered through `PluginRegistry::link`.
fn linked() -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(
            statement("secret"),
            &busbar_secret_vault_plugin::BUSBAR_COLD_ENTRY,
        )])
        .expect("the linked door admits the module")
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir =
        std::env::temp_dir().join(format!("hashicorp-vault-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libsecret.so", lib).unwrap();
    std::fs::write(dir.join("secret.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed module scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// What one door does with the module opened under `cfg`, as one comparable transcript: the row the
/// name resolves to (and the row its alias resolves to), then each reference's resolution.
fn transcript(registry: &PluginRegistry, cfg: &str) -> Vec<String> {
    let p = registry.resolve(NAME).expect("the name resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let by_alias = registry.resolve(ALIAS).map(|a| a.manifest.name.clone());
    let module = registry
        .open_secret(ALIAS, cfg)
        .expect("the module opens through its alias");
    let references = [
        serde_json::json!({ "path": "kv/data/openai#api_key" }),
        serde_json::json!({ "path": "kv/data/openai", "field": "org" }),
        serde_json::json!({ "path": "kv/data/openai#nope" }),
        serde_json::json!({ "path": "kv/data/absent#api_key" }),
        serde_json::json!({ "path": "kv/data/denied#api_key" }),
        serde_json::json!({ "path": "kv/data/openai" }),
        serde_json::json!({}),
    ];
    let mut out = vec![
        serde_json::to_string(&stated).unwrap(),
        format!("alias -> {by_alias:?}"),
    ];
    out.extend(
        references
            .iter()
            .map(|r| match module.resolve(r.as_object().unwrap()) {
                Ok(bytes) => format!("Ok({})", String::from_utf8_lossy(&bytes)),
                Err(e) => format!("Err({e:?})"),
            }),
    );
    out.push(
        match module.resolve_with_deadline(references[0].as_object().unwrap(), Some(5_000)) {
            Ok(bytes) => format!("Ok({})", String::from_utf8_lossy(&bytes)),
            Err(e) => format!("Err({e:?})"),
        },
    );
    out
}

/// The Vault module registers ONE row and behaves as ONE module through either door — and the RED
/// arms show the comparison is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_vault_module_are_one_module() {
    let addr = spawn_kv();
    let cfg = config(&addr, TOKEN);
    let lib = cdylib();
    let linked = transcript(&linked(), &cfg);
    let dropped_registry = dropped("dropped", statement("secret"), &lib);
    let dropped_in = transcript(&dropped_registry, &cfg);
    assert_eq!(linked, dropped_in, "the two doors are not one module");

    // Not a vacuous pass: each reference reached the responder and came back as the module reads it.
    let text = linked.join("\n");
    assert_eq!(linked[2], "Ok(sk-conformance)", "{text}");
    assert_eq!(linked[3], "Ok(acme)", "{text}");
    assert!(linked[4].contains("kind: NotFound"), "{text}");
    assert!(
        linked[5].contains("kind: NotFound") && linked[5].contains("404"),
        "{text}"
    );
    assert!(linked[6].contains("kind: Denied"), "{text}");
    assert!(linked[7].contains("kind: Invalid"), "{text}");
    assert!(linked[8].contains("kind: Invalid"), "{text}");
    assert_eq!(linked[9], "Ok(sk-conformance)", "{text}");

    // RED ARM 1: the same cdylib under a different operator config (another token) is a different
    // transcript — the read the linked door answered is now denied.
    let other = transcript(&dropped_registry, &config(&addr, "s.someone-else"));
    assert_ne!(
        other, linked,
        "a different config must not read as the same module"
    );
    assert!(other[2].contains("kind: Denied"), "{other:?}");

    // RED ARM 2: the same bytes signed as `auth` are refused at the kind handshake.
    let wrong = dropped("as-auth", statement("auth"), &lib);
    let e = match wrong.open_auth(ALIAS, &cfg) {
        Ok(_) => panic!("a secret library signed as auth must not open"),
        Err(e) => e,
    };
    assert!(
        e.contains(&format!(
            "plugin '{NAME}' exports kind 'secret' but is being loaded as 'auth'"
        )),
        "{e}"
    );
}
