# Contributing to busbar-secret-vault

Thanks for your interest in improving `busbar-secret-vault`. This document covers how
to build, test, and submit changes.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

`busbar-secret-vault` is a Rust `cdylib` plugin. You need a recent stable toolchain
(`rustup` recommended; `rust-toolchain.toml` pins CI's version). busbar is a
git dependency pinned to the commit in `.busbar-ref` — no sibling checkout is
needed; see the README's [Dependencies](README.md#dependencies) section.

The end-to-end test needs a real Vault dev-mode server:

```bash
docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
```

```bash
cargo build --release                       # cdylib
BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test
cargo clippy --all-targets -- -D warnings    # lints must be clean
cargo fmt --all -- --check                   # format before committing
```

Without a running Vault, `cargo test` still runs every hermetic unit test; the
end-to-end test in `secret-vault-plugin/tests/e2e.rs` self-skips locally with a
message (it hard-fails instead of skipping under CI — see the README's
[Tests](README.md#tests) section).

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** (against a real local Vault, see above) — green,
   including the end-to-end `dlopen`/Vault test in `secret-vault-plugin/tests/e2e.rs`
   — it must never be allowed to quietly skip under CI.
4. Add or update tests for any behavior change.
5. Update documentation (`README.md`, doc comments) when you change behavior or config.

## Architecture

This repo is a 2-crate workspace, not a thin adapter reaching back into busbar
for its real logic:

- `secret-vault/` (crate `busbar-secret-vault`) — the real Vault KV v2 HTTP
  client: field addressing, response-size capping, error classification.
  Most substantive Vault-logic changes belong here.
- `secret-vault-plugin/` (crate `busbar-secret-vault-plugin`) — the thin
  `cdylib` adapter: turns the engine's JSON config into a `VaultConfig`/
  `VaultSecretModule` (from the sibling `busbar-secret-vault` crate) and hands the
  trait object to
  [`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract)'s `abi::sdk`,
  which emits the C ABI symbols the loader resolves.

Changes to the ABI-crossing seam (`secret-vault-plugin/src/lib.rs`) deserve
extra care: it hands real secret material back across the plugin ABI.

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
