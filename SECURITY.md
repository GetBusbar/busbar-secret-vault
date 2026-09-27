# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/busbar-secret-vault/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/busbar-secret-vault/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`hashicorp-vault` is a `kind: secret` busbar plugin: it is the seam that resolves a
config secret **reference** (`{ module: vault, settings: { path: ... } }`) into the
real secret bytes busbar hands to the rest of the engine — provider API keys, the
admin token, TLS key material. A defect here can leak secret material, resolve the
wrong secret, or hand back stale/attacker-controlled bytes. Issues of particular
interest include:

- Secret material logged, cached to disk, or otherwise persisted anywhere other
  than the resolved in-memory value.
- A malformed or attacker-influenced Vault response being accepted as a valid
  secret instead of failing closed.
- TLS verification bypass or weakening when talking to the configured Vault
  `addr` (including via a maliciously supplied `ca_cert_pem`).
- Token handling errors that leak the `X-Vault-Token` (e.g. in error messages
  or logs).
- A load-time config error surfacing as a silent success instead of a clean `Err`
  across the plugin ABI.
- Response-size handling that allows a hostile or misbehaving Vault endpoint to
  exhaust memory (see `MAX_VAULT_RESPONSE_BYTES` in `busbar-hashicorp-vault`).

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside.

## Supported versions

This plugin is versioned independently of busbar (see the README's
[Versioning](README.md#versioning) section). Security fixes are applied to the
latest `main` and the most recent tagged release of **this repository**. Pin to a
tag for production use.
