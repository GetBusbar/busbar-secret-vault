// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the Vault plugin on the secret kind's table (`busbar_contract::abi::secret`), every
//! slot a [`SafeSlot`] over the SDK's safe surface — no `unsafe` in this crate.
//!
//! * `validate` — the settings parse as 1.5.5's open-time config, refusing with its texts.
//! * `open` — the same parse, plus the token: the Statement names `token` as its one secret
//!   reference, so the kernel resolves it and lends the material in `OpenIn::secrets[0]`.
//! * `refresh` — a reload's new settings and re-resolved token replace the client; a refusal keeps
//!   the running one.
//! * `resolve` — a reference to its field's material, READY under a lease, FAILED with its
//!   `ERROR_KIND_*` and 1.5.5's text, or PENDING while the host's exchange runs.
//! * `release` — the lease's material is zeroed and dropped. `close` drops the state, zeroing every
//!   held lease and the token.
//! * `tick`, `retire`, `drive` — nothing to do: a KV v2 read carries no Vault lease to renew.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::{Instance, Lent, LentList, Safe, SafeSlot};
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

/// Refusal texts for calls that mint no instance (`validate`, `open`) or keep the old one
/// (`refresh`): each distinct text is held for the process's life, so the pointer an `out` names
/// never dangles. Operator-facing texts only — never material.
static HELD_TEXTS: Mutex<BTreeSet<Box<str>>> = Mutex::new(BTreeSet::new());

/// `text`, held, as an [`AbiStr`].
fn held(text: String) -> AbiStr {
    let mut texts = HELD_TEXTS.lock().unwrap_or_else(PoisonError::into_inner);
    let text: Box<str> = text.into();
    let kept = match texts.get(&text) {
        Some(k) => k,
        None => {
            texts.insert(text.clone());
            texts.get(&text).expect("just inserted")
        }
    };
    AbiStr {
        ptr: kept.as_ptr(),
        len: kept.len(),
    }
}

/// FAILED with `text` on `head`.
fn refuse(head: &mut OutHead, text: String) -> Outcome {
    head.error = held(text);
    Outcome::Failed
}

/// The token material `secrets` lends, required non-empty.
fn token(secrets: LentList<'_, Blob>) -> Result<Vec<u8>, String> {
    match secrets.get(0).map(|b| b.bytes()) {
        Some(t) if !t.is_empty() => Ok(t.to_vec()),
        _ => Err(format!(
            "invalid hashicorp-vault plugin config: `{}` resolved to no secret material",
            crate::TOKEN_KEY
        )),
    }
}

/// A client from settings bytes and the lent secrets.
fn client(settings: &[u8], secrets: LentList<'_, Blob>) -> Result<VaultClient, String> {
    let cfg = parse_config(settings)?;
    let token = token(secrets)?;
    Ok(VaultClient::new(&cfg, &token))
}

/// The host's framed one-shot http exchange over this plugin's need. The host's exchange is not
/// reachable from a safe plugin on this ABI revision (no conn table is lent, and the SDK holds no
/// safe exchange helper), so every exchange answers the transport failure naming that.
#[derive(Debug, Default)]
pub struct HostExchange;

impl Exchange for HostExchange {
    fn exchange(&self, _ticket: (u32, u32), _request: &Request) -> Exchanged {
        Exchanged::Done(Err(
            "the host lends this plugin no http exchange for its declared need".to_string(),
        ))
    }
}

/// Resolved material held under its lease, and the per-ticket refusal texts.
#[derive(Default)]
pub struct Leases {
    next: AtomicU64,
    held: Mutex<BTreeMap<u64, Vec<u8>>>,
    errors: Mutex<BTreeMap<(u32, u32), Box<str>>>,
}

impl std::fmt::Debug for Leases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leases")
            .field("held", &self.held())
            .finish_non_exhaustive()
    }
}

impl Drop for Leases {
    fn drop(&mut self) {
        let held = self.held.get_mut().unwrap_or_else(PoisonError::into_inner);
        for m in held.values_mut() {
            m.fill(0);
        }
    }
}

impl Leases {
    /// How many leases are held.
    pub fn held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Answer `result` into `out` for the call `head` names: READY with the material under a new
    /// lease (no lease for empty material), or FAILED with its code and text, held for the ticket
    /// until its next op.
    pub fn answer(
        &self,
        head: &InHead,
        result: SecretResult<Vec<u8>>,
        out: &mut ResolveOut,
    ) -> Outcome {
        let key = (head.ticket.slot, head.ticket.generation);
        let mut errors = self.errors.lock().unwrap_or_else(PoisonError::into_inner);
        errors.remove(&key);
        match result {
            Ok(material) if material.is_empty() => {
                out.error_kind = ERROR_KIND_UNSET;
                Outcome::Ready
            }
            Ok(material) => {
                let lease = self.next.fetch_add(1, Ordering::Relaxed) + 1;
                out.secret = Blob {
                    ptr: material.as_ptr(),
                    len: material.len(),
                    fmt: BLOB_OCTETS,
                    flags: BLOB_SECRET,
                };
                out.head.lease = lease;
                out.error_kind = ERROR_KIND_UNSET;
                // The Vec's heap buffer does not move when the map takes the Vec.
                self.held
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(lease, material);
                Outcome::Ready
            }
            Err(e) => {
                let text: Box<str> = e.message.into();
                out.head.error = AbiStr {
                    ptr: text.as_ptr(),
                    len: text.len(),
                };
                out.error_kind = error_kind(e.kind);
                errors.insert(key, text);
                Outcome::Failed
            }
        }
    }

    /// Release `lease`: its material is zeroed and dropped. An unknown lease is REFUSED.
    pub fn release(&self, lease: u64) -> Outcome {
        let taken = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&lease);
        match taken {
            Some(mut m) => {
                m.fill(0);
                Outcome::Ready
            }
            None => Outcome::Refused,
        }
    }

    /// Forget the refusal text held for `ticket`.
    fn forget(&self, ticket: (u32, u32)) {
        self.errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket);
    }
}

/// One instance: the client (swapped whole on `refresh`), the exchange and the leases.
pub struct Vault {
    client: RwLock<Arc<VaultClient>>,
    exchange: Box<dyn Exchange + Send + Sync>,
    leases: Leases,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("leases", &self.leases)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// An instance over `client`, exchanging through `exchange`.
    pub fn new(client: VaultClient, exchange: Box<dyn Exchange + Send + Sync>) -> Self {
        Self {
            client: RwLock::new(Arc::new(client)),
            exchange,
            leases: Leases::default(),
        }
    }

    /// The current client.
    fn client(&self) -> Arc<VaultClient> {
        self.client
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The leases.
    pub fn leases(&self) -> &Leases {
        &self.leases
    }

    /// `resolve` for the op `head` names, over its settings bytes: the answer written to `out`.
    pub fn resolve(&self, head: &InHead, settings: &[u8], out: &mut ResolveOut) -> Outcome {
        let ticket = (head.ticket.slot, head.ticket.generation);
        let result = match settings_of(settings) {
            Err(e) => Some(Err(e)),
            Ok(s) => self.client().resolve(&s, self.exchange.as_ref(), ticket),
        };
        match result {
            None => {
                self.leases.forget(ticket);
                Outcome::Pending
            }
            Some(r) => self.leases.answer(head, r, out),
        }
    }
}

/// `validate`: the settings as 1.5.5's open-time config.
pub struct Validate;

impl SafeSlot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    type State = Vault;
    fn call(_: Instance<'_, Vault>, input: Lent<'_, ValidateIn>, out: &mut OutHead) -> Outcome {
        match parse_config(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(e) => refuse(out, e),
        }
    }
}

/// `open`: the client from the settings and the resolved token.
pub struct Open;

impl SafeSlot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    type State = Vault;
    fn call(instance: Instance<'_, Vault>, input: Lent<'_, OpenIn>, out: &mut OpenOut) -> Outcome {
        match client(input.field(|i| &i.settings).bytes(), input.secrets()) {
            Ok(c) => {
                instance.open(Vault::new(c, Box::new(HostExchange)));
                Outcome::Ready
            }
            Err(e) => refuse(&mut out.head, e),
        }
    }
}

/// `refresh`: a reload's settings and token replace the client; a refusal keeps the running one.
pub struct Refresh;

impl SafeSlot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    type State = Vault;
    fn call(
        instance: Instance<'_, Vault>,
        input: Lent<'_, RefreshIn>,
        out: &mut OutHead,
    ) -> Outcome {
        let Some(v) = instance.get() else {
            return Outcome::Refused;
        };
        match client(input.field(|i| &i.settings).bytes(), input.secrets()) {
            Ok(c) => {
                *v.client.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(c);
                Outcome::Ready
            }
            Err(e) => refuse(out, e),
        }
    }
}

/// `resolve`: see [`Vault::resolve`].
pub struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Vault;
    fn call(
        instance: Instance<'_, Vault>,
        input: Lent<'_, ResolveIn>,
        out: &mut ResolveOut,
    ) -> Outcome {
        let Some(v) = instance.get() else {
            return Outcome::Refused;
        };
        let head = input.head;
        v.resolve(&head, input.field(|i| &i.settings).bytes(), out)
    }
}

/// `release`: zeroes and drops the lease's material.
pub struct Release;

impl SafeSlot for Release {
    type In = ReleaseIn;
    type Out = OutHead;
    type State = Vault;
    fn call(instance: Instance<'_, Vault>, input: Lent<'_, ReleaseIn>, _: &mut OutHead) -> Outcome {
        instance
            .get()
            .map_or(Outcome::Refused, |v| v.leases.release(input.lease))
    }
}

/// `cancel`: a pending resolve is aborted before any lease was granted.
pub struct Cancel;

impl SafeSlot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    type State = Vault;
    fn call(
        instance: Instance<'_, Vault>,
        input: Lent<'_, CancelIn>,
        out: &mut CancelOut,
    ) -> Outcome {
        if let Some(v) = instance.get() {
            v.leases
                .forget((input.ticket.slot, input.ticket.generation));
        }
        out.disposition = cancel::ABORTED;
        Outcome::Ready
    }
}

/// `tick`: no background work (a KV v2 read carries no Vault lease); never tick again.
pub struct Tick;

impl SafeSlot for Tick {
    type In = TickIn;
    type Out = TickOut;
    type State = Vault;
    fn call(_: Instance<'_, Vault>, _: Lent<'_, TickIn>, out: &mut TickOut) -> Outcome {
        out.next_tick_ns = 0;
        Outcome::Ready
    }
}

macro_rules! ready_slot {
    ($(#[$doc:meta] $name:ident: $in:ty => $out:ty;)*) => {$(
        #[$doc]
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Vault;
            fn call(_: Instance<'_, Vault>, _: Lent<'_, $in>, _: &mut $out) -> Outcome {
                Outcome::Ready
            }
        }
    )*};
}

ready_slot! {
    /// `retire`: leases outlive a generation until released.
    Retire: GenIn => OutHead;
    /// `drive`: no driver.
    Drive: DriveIn => OutHead;
    /// `close`: the SDK drops the state (zeroing every held lease and the token) on READY.
    Close: InHead => OutHead;
}

mod table {
    use super::{
        Cancel, Close, Drive, Open, Refresh, Release, Resolve, Retire, Safe, Tick, Validate,
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: super::STATEMENT,
        lifecycle: {
            validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>,
            retire: Safe<Retire>, tick: Safe<Tick>, drive: Safe<Drive>,
            cancel: Safe<Cancel>, release: Safe<Release>, close: Safe<Close>,
        },
        kind_ops: { resolve: Safe<Resolve> },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
