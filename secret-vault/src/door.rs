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

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{self as sdk, Op};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut, ERROR_KIND_UNSET};
use busbar_contract::secret::SecretResult;

use crate::{error_kind, parse_config, settings_of, Exchange, Exchanged, Request, VaultClient};

/// The settings keys whose values are secret references, in `OpenIn::secrets` order.
const SECRET_REFS: &[AbiStr] = &[abi_str(crate::TOKEN_KEY)];

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The config path the target comes from: the `addr` setting (the host resolves it at `open` and
/// `refresh` and pins every exchange of the need to it).
const TARGET_FROM: &str = "settings.addr";
/// The config path the operator CA comes from (1.5.5's `ca_cert_pem`): added on top of the public
/// roots by the host's TLS, never handed to this plugin.
const TRUST_FROM: &str = "settings.ca_cert_pem";

/// The need over the public roots: a Vault reached with the host's default trust.
pub const NEED_PUBLIC: u32 = 0;
/// The need over the operator's CA (`ca_cert_pem`): the same target, its TLS trusting that CA too.
pub const NEED_OPERATOR_CA: u32 = 1;

/// One outbound need framed by the `http` transport to the `addr` setting's target, in the
/// operator-infrastructure egress class (a Vault is the operator's own service: its address may be
/// private, and `http://` is the operator's choice), trusting `trust_from`'s CA when it names one.
const fn need(trust_from: AbiStr) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
        transport: abi_str("http"),
        auth: NONE,
        target_from: abi_str(TARGET_FROM),
        trust_from,
        details: Blob::ABSENT,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        // The response head is not read: the named (empty) list.
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }
}

/// The two needs, by index: [`NEED_PUBLIC`] and [`NEED_OPERATOR_CA`]. A configuration with no
/// `ca_cert_pem` leaves the second undeclared (its trust resolved to nothing), and every read goes
/// over the first.
const NEEDS: &[Need] = &[need(NONE), need(abi_str(TRUST_FROM))];

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight, the
/// token as its one secret reference, and its needs.
pub const STATEMENT: Statement = Statement {
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
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

/// THE HOST'S FRAMED ONE-SHOT HTTP EXCHANGE over this plugin's declared need, for the op on its
/// ticket (the SDK's [`Op`]): the request goes over [`NEED_OPERATOR_CA`] when it names an operator
/// CA, else over [`NEED_PUBLIC`], to the need's target (`addr`), at the request's path; PENDING
/// while it runs (the op is re-entered on its wake and the parked exchange resumed).
pub struct HostExchange<'a> {
    op: Op<'a>,
}

impl std::fmt::Debug for HostExchange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostExchange").finish_non_exhaustive()
    }
}

impl<'a> HostExchange<'a> {
    /// The exchange the op `instance` runs over the host tables `open` handed it.
    pub fn new<'b: 'a, T: Send + Sync + 'static>(
        instance: &'a Instance<'b, T>,
        host: Option<&'a Host>,
    ) -> Self {
        Self {
            op: Op::new(instance, host),
        }
    }
}

/// The path and query of `url` (`/v1/kv/data/x`), the target the framed request names.
fn path_of(url: &str) -> String {
    url.parse::<http::Uri>()
        .ok()
        .and_then(|u| u.path_and_query().map(|p| p.as_str().to_owned()))
        .unwrap_or_else(|| "/".to_owned())
}

impl Exchange for HostExchange<'_> {
    fn exchange(&self, _ticket: (u32, u32), request: &Request) -> Exchanged {
        let need = if request.trust_pem.is_some() {
            NEED_OPERATOR_CA
        } else {
            NEED_PUBLIC
        };
        let answered = self.op.exchange(need, None, || {
            Ok(sdk::Request {
                method: request.method.as_bytes().to_vec(),
                target: path_of(&request.url).into_bytes(),
                fields: request
                    .fields
                    .iter()
                    .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
                    .collect(),
                body: Vec::new(),
                timeout_ms: request.timeout_ms,
            })
        });
        match answered {
            std::task::Poll::Pending => Exchanged::Pending,
            std::task::Poll::Ready(Err(e)) => Exchanged::Done(Err(e.to_string())),
            std::task::Poll::Ready(Ok(r)) => {
                let body_len = r.body.len();
                let mut body = r.body;
                body.truncate(request.body_cap);
                Exchanged::Done(Ok(crate::Response {
                    status: r.status,
                    body,
                    body_len,
                }))
            }
        }
    }
}

/// One instance: the client (swapped whole on `refresh`), and the exchange a test stands in for
/// the host's (`None`: each op's own [`HostExchange`]).
pub struct Vault {
    client: RwLock<Arc<VaultClient>>,
    exchange: Option<Box<dyn Exchange + Send + Sync>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

impl Vault {
    /// An instance over `client`, exchanging through `exchange` (a test's stand-in for the host).
    pub fn new(client: VaultClient, exchange: Box<dyn Exchange + Send + Sync>) -> Self {
        Self {
            client: RwLock::new(Arc::new(client)),
            exchange: Some(exchange),
        }
    }

    /// An instance over `client`, each op exchanging through the host ([`HostExchange`]).
    #[must_use]
    pub fn over_host(client: VaultClient) -> Self {
        Self {
            client: RwLock::new(Arc::new(client)),
            exchange: None,
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
        match &self.exchange {
            Some(exchange) => self.resolve_over(exchange.as_ref(), ticket, settings),
            None => Some(Err(busbar_contract::secret::SecretModuleError::new(
                busbar_contract::secret::SecretErrorKind::Unavailable,
                "the host lends this instance no exchange outside an op",
            ))),
        }
    }

    /// `resolve` over `exchange` (the op's [`HostExchange`], or a test's stand-in).
    pub fn resolve_over(
        &self,
        exchange: &dyn Exchange,
        ticket: Ticket,
        settings: &[u8],
    ) -> Option<SecretResult<Vec<u8>>> {
        match settings_of(settings) {
            Err(e) => Some(Err(e)),
            Ok(s) => self
                .client()
                .resolve(&s, exchange, (ticket.slot, ticket.generation)),
        }
    }

    /// Whether this instance exchanges through the host (no test stand-in).
    fn over_the_host(&self) -> bool {
        self.exchange.is_none()
    }
}

impl Life for Vault {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse_config(settings).map(|_| ()).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Vault::over_host(client(settings, secrets)?))
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
        let vault = held.life();
        let answered = if vault.over_the_host() {
            let exchange = HostExchange::new(&instance, held.host());
            vault.resolve_over(&exchange, instance.ticket(), settings)
        } else {
            vault.resolve(instance.ticket(), settings)
        };
        match answered {
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
