// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the Vault plugin on the secret kind's table (`busbar_contract::abi::secret`), the nine
//! lifecycle slots the SDK's generic lifecycle (`lifecycle: life(Vault)`, [`Life`]) and `resolve` a
//! [`SafeSlot`] — no `unsafe` in this crate.
//!
//! * `validate` — the settings parse as 1.5.5's open-time config, refusing with its texts.
//! * `open` — the same parse, plus the token: the Statement names `token` as its one secret
//!   reference, so the kernel resolves it and lends the material in `OpenIn::secrets[0]`.
//! * `refresh` — a reload's new settings and re-resolved token replace the client; a refusal keeps
//!   the running one.
//! * `resolve` — a reference to its field's material, READY under a lease (the SDK's [`Held`]
//!   leases, zeroed on release), FAILED with its `ERROR_KIND_*` and 1.5.5's text, or PENDING while
//!   the host's exchange runs.
//! * `release`, `close`, `cancel`, `tick`, `retire`, `drive` — the SDK's: a KV v2 read carries no
//!   Vault lease to renew.

use std::sync::{Arc, PoisonError, RwLock};

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut, ERROR_KIND_UNSET};
use busbar_contract::secret::SecretResult;

use crate::{error_kind, parse_config, settings_of, Exchange, Exchanged, Request, VaultClient};

/// The settings keys whose values are secret references, in `OpenIn::secrets` order.
const SECRET_REFS: &[AbiStr] = &[abi_str(crate::TOKEN_KEY)];

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight, and
/// the token as its one secret reference.
pub const STATEMENT: Statement = Statement {
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    ..statement(crate::NAME, env!("CARGO_PKG_VERSION"), 64)
};

/// The token material `secrets` lends, required non-empty.
fn token<'a>(secrets: &[&'a [u8]]) -> Result<&'a [u8], String> {
    match secrets.first() {
        Some(t) if !t.is_empty() => Ok(*t),
        _ => Err(format!(
            "invalid hashicorp-vault plugin config: `{}` resolved to no secret material",
            crate::TOKEN_KEY
        )),
    }
}

/// A client from settings bytes and the lent secrets.
fn client(settings: &[u8], secrets: &[&[u8]]) -> Result<VaultClient, Refusal> {
    let cfg = parse_config(settings).map_err(Refusal::failed)?;
    let token = token(secrets).map_err(Refusal::failed)?;
    Ok(VaultClient::new(&cfg, token))
}

/// The host's framed one-shot http exchange over this plugin's need. This plugin declares no need
/// and is lent no connector yet, so every exchange answers the transport failure naming that.
#[derive(Debug, Default)]
pub struct HostExchange;

impl Exchange for HostExchange {
    fn exchange(&self, _ticket: (u32, u32), _request: &Request) -> Exchanged {
        Exchanged::Done(Err(
            "the host lends this plugin no http exchange for its declared need".to_string(),
        ))
    }
}

/// One instance: the client (swapped whole on `refresh`) and the exchange.
pub struct Vault {
    client: RwLock<Arc<VaultClient>>,
    exchange: Box<dyn Exchange + Send + Sync>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

impl Vault {
    /// An instance over `client`, exchanging through `exchange`.
    pub fn new(client: VaultClient, exchange: Box<dyn Exchange + Send + Sync>) -> Self {
        Self {
            client: RwLock::new(Arc::new(client)),
            exchange,
        }
    }

    /// The current client.
    fn client(&self) -> Arc<VaultClient> {
        self.client
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `resolve` for the op on `ticket`, over its settings bytes: `None` while the exchange is
    /// pending.
    pub fn resolve(&self, ticket: Ticket, settings: &[u8]) -> Option<SecretResult<Vec<u8>>> {
        match settings_of(settings) {
            Err(e) => Some(Err(e)),
            Ok(s) => {
                self.client()
                    .resolve(&s, self.exchange.as_ref(), (ticket.slot, ticket.generation))
            }
        }
    }
}

impl Life for Vault {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse_config(settings).map(|_| ()).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Vault::new(
            client(settings, secrets)?,
            Box::new(HostExchange),
        ))
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let c = client(settings, secrets)?;
        *self.client.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(c);
        Ok(Refreshed::default())
    }
}

/// `resolve`: see [`Vault::resolve`]. READY with the material under a lease (none for empty
/// material), FAILED with its code and text, PENDING while the exchange runs.
pub struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Vault>;
    fn call(
        instance: Instance<'_, Held<Vault>>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let settings = input.field(|i| &i.settings).bytes();
        match held.life().resolve(instance.ticket(), settings) {
            None => Outcome::Pending,
            Some(Ok(material)) => {
                out.lease_secret(|o| &o.secret, held.leases(), material, BLOB_OCTETS);
                out.set(|o| &o.error_kind, ERROR_KIND_UNSET);
                Outcome::Ready
            }
            Some(Err(e)) => {
                out.set(|o| &o.error_kind, error_kind(e.kind));
                out.fail(Refusal::failed(e.message))
            }
        }
    }
}

mod table {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: super::STATEMENT,
        lifecycle: life(super::Vault),
        kind_ops: { resolve: super::Safe<super::Resolve> },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
