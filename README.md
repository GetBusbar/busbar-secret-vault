# hashicorp-vault

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/busbar-secret-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/busbar-secret-vault/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GetBusbar/busbar-secret-vault)](https://github.com/GetBusbar/busbar-secret-vault/releases)
[![Coverage](https://codecov.io/gh/GetBusbar/busbar-secret-vault/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-secret-vault)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: secret` plugin for
[busbar](https://getbusbar.com): resolves a config secret **reference**
against a real [HashiCorp Vault](https://www.vaultproject.io) KV v2
secrets engine over its HTTP API — a genuine client (no mock), reading
one field out of a `kv-v2` entry and authenticating with a pre-obtained
`X-Vault-Token`.

It is a `cdylib` that implements busbar's `SecretModule` trait (via
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process.

## Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.5.0+** (the release that ships the
signed hybrid plugin ABI this crate loads over). Pin both versions
explicitly in production; do not assume they move together.

## What it is for

Every secret value in busbar's config — a provider `api_key`,
`auth.signing_key`, the admin token, a TLS `cert`/`key`/`client_ca` — is a
secret **reference**, not a literal. The two built-in reference forms
(`{ env: VAR }` and `{ file: /path }`) need no plugin. This plugin adds a
third form, `{ module: vault, settings: {...} }`, so a reference resolves
from a real Vault server through the same signed-plugin trust pipeline —
the plugin you reach for when key material must never sit in an env var
or an on-disk file.

## Design

This repo brings 100% of what it needs — it is a 2-crate Cargo workspace,
not a thin adapter pointing back at busbar for its real logic:

- **`hashicorp-vault/`** (crate `busbar-hashicorp-vault`) — the real Vault KV v2
  HTTP client: field addressing, response-size capping, and 404/403/5xx
  error classification. Usable statically, independent of the plugin ABI.
- **`hashicorp-vault-plugin/`** (crate `busbar-hashicorp-vault-plugin`, `src/lib.rs`
  ~45 lines) — the thin `cdylib` adapter: turns the engine's JSON
  open-time config into a real `VaultSecretModule` (from the sibling
  `hashicorp-vault` crate, a same-repo path dependency) and hands the trait
  object to the SDK, which emits the extern-C symbols the loader
  resolves.

Auth is deliberately scoped to exactly one Vault auth method: a
pre-obtained token sent as `X-Vault-Token` — Vault's simplest and most
universal scheme, and the right initial surface for a first version.
AppRole/Kubernetes login flows are a natural future extension of
`busbar-hashicorp-vault` itself, not the thin ABI adapter.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)); `rust-toolchain.toml` pins
the version CI uses. busbar is a pinned git dependency (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # workspace build; cdylib at target/release/libbusbar_hashicorp_vault_plugin.{so,dylib}
cargo test                 # both crates' unit tests + the end-to-end loader/Vault test (see hashicorp-vault-plugin/tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

`busbar-hashicorp-vault` (`hashicorp-vault/`) is a same-repo crate; `hashicorp-vault-plugin`
depends on it as a normal workspace path dependency (`../hashicorp-vault`).

The one [busbar](https://github.com/GetBusbar/busbar) crate either crate
names is `busbar-contract` — the plugin contract, whose `abi::sdk` module
carries the export macros. `busbar-plugin-loader` is a dev-dependency only,
for the linked + dropped-in conformance test and the end-to-end test. Both
are **git dependencies pinned to one busbar commit**: the `rev` in every
`Cargo.toml` is field 1 of `.busbar-ref`, and CI's `pin` job refuses a
manifest that disagrees. No sibling checkout of busbar is needed to build
or test; the live end-to-end test (`tests/e2e.rs`) builds the real `busbar`
binary from a checkout named by `BUSBAR_CHECKOUT` (CI's `e2e` job provides
one at `.busbar-ref`).

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_hashicorp_vault_plugin.so \
    --name busbar-hashicorp-vault --alias vault --kind secret \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-hashicorp-vault-1.0.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir`, add a
`secrets:` entry naming the module's own open-time config (the Vault
address + token), and reference it from any secret field — see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#secret-plugins-kind-secret)
for the full `secrets:` wiring reference. Example: enable the plugin and
point `plugins.enabled: true` at a directory containing the tarball, then

```yaml
plugins:
  enabled: true
  dir: plugins

secrets:
  vault:
    settings:
      addr: "https://vault.internal:8200"
      token: { env: VAULT_TOKEN }

providers:
  openai:
    api_key: { module: vault, settings: { path: "kv/data/openai#api_key" } }
```

`secrets.<alias>` is keyed by the module's alias (`vault`, matching the
signed manifest's `alias` field) and carries the module's own open-time
`settings` — the Vault address and auth, resolved once when the plugin is
opened. A field reference like `providers.openai.api_key` then names
`{ module: vault, settings: { path } }`, where `path` is the full Vault
v1 API path INCLUDING the KV v2 `data/` segment (exactly what `vault kv
get`/the Vault UI show), with the field to extract named either as a
`#field` suffix (as above) or a separate `field` key — see
[Config](#config) below for both forms.

## Config

### Module open-time config (`secrets.<alias>.settings`)

| Setting | Required | Default | Notes |
|---|---|---|---|
| `addr` | yes | — | The Vault server address, e.g. `https://vault.internal:8200` (or `http://127.0.0.1:8200` for a local dev-mode server). |
| `token` | yes | — | The Vault token sent as `X-Vault-Token` on every read. Should be delivered as a secret reference (`{ env: VAULT_TOKEN }`), never a plaintext literal — module-level settings cannot reference another secret plugin, only the built-in `env`/`file` modules. |
| `ca_cert_pem` | no | — | An additional trusted root CA (PEM), layered on top of the built-in public root store — for a self-hosted Vault behind a private CA. Never disables certificate validation. |
| `timeout_secs` | no | `10` | HTTP timeout (connect + total), in seconds. |

Unknown config fields are rejected (`deny_unknown_fields`) — a typo'd or
stray key fails loudly at boot instead of being silently ignored.

### Per-reference settings (`{ module: vault, settings: {...} }`)

A Vault KV v2 entry commonly holds multiple key/value pairs (e.g.
`kv/data/openai` might hold both `api_key` and `org_id`), so a reference
must name which field to extract, in one of two equivalent forms:

| Form | Example |
|---|---|
| `#field` suffix on `path` | `{ "path": "kv/data/openai#api_key" }` |
| separate `field` key | `{ "path": "kv/data/openai", "field": "api_key" }` |

If both are given, the explicit `field` key wins. `path` is used verbatim
after `{addr}/v1/` — this plugin never prepends a mount or a `data/`
segment itself.

A 404 (no secret at that path), a 403 (bad token / missing Vault
policy), and a 5xx (Vault itself unhealthy) each surface as a distinct,
specific error — never collapsed into a generic "resolve failed", and
never an empty `Ok`.

## Tests

`cargo test` (run at the workspace root) runs `hashicorp-vault`'s own
hermetic unit tests (reference-parsing, the response-size cap, and —
gated on `BUSBAR_TEST_VAULT_ADDR`/`BUSBAR_TEST_VAULT_TOKEN` — a real
round trip), `hashicorp-vault-plugin`'s own hermetic unit tests (covering
`open()`'s config-parsing responsibility: empty/malformed/
missing-required-field/unknown-field config, all without any network
I/O), and the end-to-end test in `hashicorp-vault-plugin/tests/e2e.rs`.

The end-to-end test is NOT a stub: it seeds a real secret directly into a
real Vault dev-mode server via a raw HTTP PUT, then `dlopen`s the
actually-built `busbar-hashicorp-vault-plugin` cdylib over
`busbar-plugin-loader`'s real `kind: secret` C ABI seam — the same seam
busbar's engine uses — and reads that secret back through it. It proves,
against a genuine Vault server:

- both field-addressing forms (`#field` suffix and explicit `field` key)
  resolve the correct value across the real C ABI;
- a missing path surfaces as a distinct, loud 404 — never an empty `Ok`;
- settings with no addressable field fail closed.

It needs a real Vault dev-mode server:

```sh
docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test
```

Without a running Vault, this test self-skips locally with a message —
but hard-fails under CI (`CI` env var set) instead of silently skipping;
this is the only over-the-ABI coverage of the real Vault-backed
`kind: secret` dlopen seam and must never quietly vanish. CI boots a real
`hashicorp/vault` dev-mode service container to provide it (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
