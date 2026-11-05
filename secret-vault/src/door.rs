// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the Vault plugin on the secret kind's table (`busbar_contract::abi::secret`), the nine
//! lifecycle slots the SDK's generic lifecycle (`lifecycle: life(Vault)`, [`Life`]) and `resolve` a
//! [`SafeSlot`] — no `unsafe` in this crate.
//!
//! * `validate` — the settings parse as the open-time config, refusing with its texts.
//! * `open` — the same parse, plus the token: the Statement names `token` as its one secret
//!   reference, so the kernel resolves it and lends the material in `OpenIn::secrets[0]`.
//! * `refresh` — a reload's new settings and re-resolved token replace the client; a refusal keeps
//!   the running one.
//! * `resolve` — a reference to its field's material, READY with the material written into the
//!   host's zeroed buffer (the SDK's `resolved`; no lease, the plugin's copy wiped), FAILED with its
//!   `ERROR_KIND_*` and its text, or PENDING while the host's exchange runs.
//! * `release`, `close`, `cancel`, `tick`, `retire`, `drive` — the SDK's: a KV v2 read carries no
//!   Vault lease to renew.

use std::sync::{Arc, PoisonError, RwLock};

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::door::{Rewrite, Statement, REWRITE_ALIAS};
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::cred::{self, resolved};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{self as sdk, Op};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::secret::{failed, settings_of};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut};
use busbar_contract::secret::SecretResult;
use zeroize::Zeroize;

use crate::{parse_config, Exchange, Exchanged, Request, VaultClient};

/// The settings keys whose values are secret references, in `OpenIn::secrets` order.
const SECRET_REFS: &[AbiStr] = &[abi_str(crate::TOKEN_KEY)];

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The config path the target comes from: the `addr` setting (the host resolves it at `open` and
/// `refresh` and pins every exchange of the need to it).
const TARGET_FROM: &str = "settings.addr";
/// The config path the operator CA comes from (`ca_cert_pem`): added on top of the public
/// roots by the host's TLS, never handed to this plugin.
const TRUST_FROM: &str = "settings.ca_cert_pem";

/// The need over the public roots: a Vault reached with the host's default trust.
pub const NEED_PUBLIC: u32 = 0;
/// The need over the operator's CA (`ca_cert_pem`): the same target, its TLS trusting that CA too.
pub const NEED_OPERATOR_CA: u32 = 1;

/// One outbound need framed by the `http` transport to the `addr` setting's target, in the
/// operator-infrastructure egress class (a Vault is the operator's own service: its address may be
/// private, and `http://` is the operator's choice), trusting `trust_from`'s CA when it names one.
/// The response head is not read: its kept-field list is the named, empty one.
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

/// A rewrite naming this source by its word ([`crate::WORD`]), in `class`, carrying `to`.
const fn rewrite(class: u32, to: &'static str) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(crate::WORD),
        to: abi_str(to),
    }
}

/// The names config gives this source: its module alias (`module: vault`). It has no shorthand.
const REWRITES: &[Rewrite] = &[rewrite(REWRITE_ALIAS, "")];

/// The settings accepted by this plugin's lifecycle parser.
const SETTINGS_SCHEMA: busbar_contract::abi::mechanism::call::Blob =
    busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json"));

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight (the
/// host clamps a secret instance to 16), the token as its one secret reference, its needs, and the
/// names config gives it.
pub const STATEMENT: Statement = Statement {
    settings_schema: SETTINGS_SCHEMA,
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(crate::NAME, env!("CARGO_PKG_VERSION"), 16)
};

/// The token material `secrets` lends, required non-empty and free of control characters (every C0
/// control but TAB, and DEL: RFC 9110 field values cannot carry them, so no `X-Vault-Token` header
/// could).
fn token<'a>(secrets: &[&'a [u8]]) -> Result<&'a [u8], String> {
    match secrets.first() {
        Some(t) if t.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7F) => Err(format!(
            "invalid hashicorp-vault plugin config: `{}` resolved to material with a control \
             character (such as CR, LF or NUL), which cannot be sent as the X-Vault-Token header",
            crate::TOKEN_KEY
        )),
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

    /// The retained whole-exchange deadline, including a pending dial or body read. The
    /// outer resolve propagates it so an otherwise silent connection is re-entered on time.
    pub fn wake_at_ns(&self) -> Option<u64> {
        self.op.wake_at_ns()
    }
}

/// The need a request goes over: [`NEED_OPERATOR_CA`] when it names an operator CA, else
/// [`NEED_PUBLIC`].
fn need_for(request: &Request) -> u32 {
    if request.trust_pem.is_some() {
        NEED_OPERATOR_CA
    } else {
        NEED_PUBLIC
    }
}

/// The framed exchange for `request`: the need it goes over, and the builder of the SDK request
/// (lazy: the op runs it only on its first entry).
fn framed(request: &Request) -> (u32, impl FnOnce() -> Result<sdk::Request, String> + '_) {
    (need_for(request), move || {
        Ok(sdk::Request {
            method: request.method.as_bytes().to_vec(),
            target: request.target.clone().into_bytes(),
            fields: request
                .fields
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.to_vec()))
                .collect(),
            body: Vec::new(),
            timeout_ms: request.timeout_ms,
        })
    })
}

impl Exchange for HostExchange<'_> {
    fn exchange(&self, request: &Request) -> Exchanged {
        self.op.set_timeout_ms(request.timeout_ms);
        let (need, build) = framed(request);
        let answered =
            self.op
                .exchange_sealed_bounded_with_head(need, None, request.body_cap, false, || {
                    build().map(|request| (request, Vec::new()))
                });
        match answered {
            std::task::Poll::Pending => Exchanged::Pending,
            std::task::Poll::Ready(answer) => bounded_reply(answer, request.body_cap),
        }
    }
}

/// The exchange's answer as the plugin's. A reply stopped at the bound still carries its actual
/// response status, answered as over the cap: the judge preserves 404/403/5xx precedence over the
/// body cap; all other statuses get the ordinary over-cap refusal.
fn bounded_reply(
    answer: Result<sdk::ExchangeResponse, sdk::ExchangeFailure>,
    cap: usize,
) -> Exchanged {
    match answer {
        Err(error) => {
            let stopped = matches!(error.cause(), sdk::OpFailure::Conn(ConnFailure::Failed(why))
                if why.as_str() == sdk::REPLY_OVER_BOUND);
            match error.head() {
                Some(head) if stopped => Exchanged::Done(Ok(crate::Response {
                    status: head.status,
                    body: Vec::new(),
                    body_len: cap.saturating_add(1),
                })),
                _ => Exchanged::Done(Err(failure_class(error.into_cause()))),
            }
        }
        Ok(reply) => Exchanged::Done(Ok(cut_to_cap(reply, cap))),
    }
}

/// The connector class of an op failure. The local request builder never fails, so a construction
/// failure is a wiring fault, never a retryable remote outage: the class stays fail closed.
fn failure_class(failure: sdk::OpFailure) -> ConnFailure {
    match failure {
        sdk::OpFailure::Conn(cause) => cause,
        sdk::OpFailure::Unbuilt(_) => ConnFailure::Fault,
    }
}

/// The exchange's reply as the plugin's [`crate::Response`]: the body is moved, cut to `cap`; what
/// lies past the cap is wiped, and the rest of the reply with it: no tail is left behind.
/// `body_len` keeps the full length so the judge can tell "at the cap" from "over it".
fn cut_to_cap(mut r: sdk::ExchangeResponse, cap: usize) -> crate::Response {
    let body_len = r.body.len();
    let kept = body_len.min(cap);
    r.body[kept..].zeroize();
    let mut body = std::mem::take(&mut r.body);
    body.truncate(kept);
    let response = crate::Response {
        status: r.status,
        body,
        body_len,
    };
    r.zeroize();
    response
}

/// One instance: the client, swapped whole on `refresh`.
pub struct Vault {
    client: RwLock<Arc<VaultClient>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

impl Vault {
    /// An instance over `client`.
    #[must_use]
    pub fn new(client: VaultClient) -> Self {
        Self {
            client: RwLock::new(Arc::new(client)),
        }
    }

    /// The current client.
    fn client(&self) -> Arc<VaultClient> {
        self.client
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `resolve` for the op over `exchange` (the op's [`HostExchange`]), over its reference's
    /// settings bytes: `None` while the exchange is pending.
    pub fn resolve(
        &self,
        exchange: &dyn Exchange,
        settings: &[u8],
    ) -> Option<SecretResult<Vec<u8>>> {
        match settings_of(settings) {
            Err(e) => Some(Err(e)),
            Ok(s) => self.client().resolve(&s, exchange),
        }
    }
}

impl Life for Vault {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse_config(settings).map(|_| ()).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Vault::new(client(settings, secrets)?))
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let c = client(settings, secrets)?;
        *self.client.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(c);
        Ok(Refreshed::default())
    }
}

/// `resolve`: see [`Vault::resolve`]. READY with the material written into the host's zeroed
/// buffer (the SDK's `resolved`; no lease, the plugin's copy wiped; an empty field is refused,
/// never resolved empty), FAILED with its code and text, PENDING while the exchange runs.
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
        let exchange = HostExchange::new(&instance, held.host());

        exchange.op.set_deadline_ns(input.head.deadline_ns);
        let answered = vault.resolve(&exchange, settings);
        match answered {
            None => {
                if let Some(deadline) = exchange.wake_at_ns() {
                    out.wake_at(deadline);
                }
                Outcome::Pending
            }
            Some(Ok(material)) => resolved(input, &mut out, cred::Held::new(material)),
            Some(Err(e)) => failed(&mut out, e),
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
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "settings_schema_tests.rs"]
mod settings_schema_tests;
