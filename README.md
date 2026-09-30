<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-secret-vault

The HashiCorp Vault secret backend as a droppable busbar plugin: a cdylib exporting the secret C ABI. Drop it in the plugins folder, add vault to secrets: with its addr/token settings, and reference secrets as { module: vault, settings: { path: "kv/data/name#field" } }.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `secret` | `vault` | `busbar-secret-vault-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-secret-vault/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-secret-vault/actions/workflows/ci.yml)
<!-- fleet:header:end -->

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

It exports the secret kind's door (via
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract))
and is loaded in-process by busbar over the secret kind's memory ABI —
compiled in, or `dlopen`'d as a signed cdylib, never a separate process.

## Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.6.0+** (the release that ships the
secret kind's memory ABI, v2, this crate loads over; 1.6.0 loads no 1.5.x
build of this plugin). Pin both versions
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

This repo brings 100% of what it needs — a 2-crate Cargo workspace on the
secret kind's **memory ABI** (`busbar_contract::abi::secret`):

- **`secret-vault/`** (crate `busbar-secret-vault`, `#![forbid(unsafe_code)]`)
  — the sans-IO Vault KV v2 client (field addressing, the request it
  sends, the 1 MiB response cap, and 404/403/5xx error classification)
  and its door, `door::door`: every slot a safe SDK slot over the secret
  kind's table. A busbar build that compiles the plugin in links this
  crate and registers that door.
- **`secret-vault-plugin/`** (crate `busbar-secret-vault-plugin`) — the
  thin `cdylib` that exports the same door as `busbar_plugin_door`, so
  compiled in or dropped in, the kernel reaches the same table.

The plugin never opens a socket, dials or does TLS. Its one read goes
through the host's framed one-shot http exchange over its declared need
(`operator-infrastructure`, the target from `addr`, `ca_cert_pem` as an
extra trusted root); a read that cannot finish now answers PENDING and
the host re-invokes it on the wake. The token is the Statement's one
secret reference: the kernel resolves `settings.token` through the
bootstrap secret plugins and hands the material to `open`. Error texts
name the path and the URL, never the token or the value.

Auth is deliberately scoped to exactly one Vault auth method: a
pre-obtained token sent as `X-Vault-Token` — Vault's simplest and most
universal scheme, and the right initial surface for a first version.
AppRole/Kubernetes login flows are a natural future extension of
`busbar-secret-vault` itself, not the thin ABI adapter.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)); `rust-toolchain.toml` pins
the version CI uses. busbar is a pinned git dependency (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # workspace build; cdylib at target/release/libbusbar_secret_vault_plugin.{so,dylib}
cargo test                 # unit tests + the linked/dropped-in conformance test (secret-vault-plugin/tests/conformance.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

`busbar-secret-vault` (`secret-vault/`) is a same-repo crate; `secret-vault-plugin`
depends on it as a normal workspace path dependency (`../secret-vault`).

The one [busbar](https://github.com/GetBusbar/busbar) crate either crate
names is `busbar-contract` — the plugin contract, whose `abi::sdk` module
carries the door macros. `busbar-plugin-loader` is a dev-dependency only,
for the linked + dropped-in conformance test. Both are **git dependencies
pinned to one busbar commit**: the `rev` in every `Cargo.toml` is field 1
of `.busbar-ref`, and CI's `pin` job refuses a manifest that disagrees.
No sibling checkout of busbar is needed to build or test.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_secret_vault_plugin.so \
    --name busbar-secret-vault --alias vault --kind secret \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-secret-vault-1.0.0-x86_64-linux.tar.gz
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

`cargo test` (run at the workspace root) runs:

- `busbar-secret-vault`'s hermetic unit tests: reference parsing, the
  request it builds, every 1.5.5 response class and its exact text, the
  body cap, a pending exchange, the config refusals, and the door's
  lease map (READY under a lease, zeroed on release, FAILED with its
  `ERROR_KIND_*`, PENDING then resumed). One test reads a real Vault
  dev-mode server, gated on `BUSBAR_TEST_VAULT_ADDR` /
  `BUSBAR_TEST_VAULT_TOKEN` (hard-fails under `CI` when unset), through
  the sans-IO client with a test-side HTTP exchange;
- `secret-vault-plugin/tests/conformance.rs`: the linked door and the
  built cdylib, loaded through busbar's real loader, driven through the
  secret kind's table over one script and compared, with RED arms for a
  wrong kind, a Statement mismatch and a wrong config.

```sh
docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test
```

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
