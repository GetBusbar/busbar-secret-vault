// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Wiped,
    Unwiped,
    Bounds,
}

#[derive(Debug)]
struct Record {
    label: &'static str,
    address: usize,
    len: usize,
    freed: bool,
    observation: Option<Observation>,
}

struct State {
    active: bool,
    records: Vec<Record>,
}

thread_local! {
    static STATE: RefCell<State> = const {
        RefCell::new(State { active: false, records: Vec::new() })
    };
}

struct Observing;

// SAFETY: allocations and physical frees use System unchanged. Registration identifies only
// the initialized byte payload of a live Vec/String/OsString, at its allocation's start. The
// saved address is used only for matching; reads use the current deallocation pointer before
// System frees it. No shared reference is retained or recreated. Owners keep the registered
// prefix initialized until deallocation, including after a length change or a wipe. Neither
// spare capacity, object layout/padding nor freed memory is read. The hook reads no unrelated
// allocation and performs no allocation itself. Metadata frees under the registry's borrow
// are skipped by try_borrow_mut; registered owners never drop while that borrow is held.
unsafe impl GlobalAlloc for Observing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forward the allocator request unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = STATE.try_with(|state| {
            let Ok(mut state) = state.try_borrow_mut() else {
                return;
            };
            if !state.active {
                return;
            }
            if let Some(record) = state
                .records
                .iter_mut()
                .find(|record| !record.freed && record.address == ptr as usize)
            {
                record.freed = true;
                record.observation = Some(if record.len > layout.size() {
                    Observation::Bounds
                } else {
                    let mut wiped = true;
                    for offset in 0..record.len {
                        // SAFETY: registration proves this prefix contains initialized bytes;
                        // the layout bounds it and this dealloc call still owns the allocation.
                        // Use its current pointer's provenance, never the saved numeric address.
                        wiped &= unsafe { ptr.add(offset).read_volatile() } == 0;
                    }
                    if wiped {
                        Observation::Wiped
                    } else {
                        Observation::Unwiped
                    }
                });
            }
        });
        // SAFETY: the observation ended before forwarding the original pointer and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Observing = Observing;

/// Register the initialized prefix of a live allocation, which stays initialized until freed.
pub(super) fn watch(label: &'static str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !state.active {
            return;
        }
        let address = bytes.as_ptr() as usize;
        if let Some(record) = state
            .records
            .iter_mut()
            .find(|record| !record.freed && record.address == address)
        {
            record.len = record.len.max(bytes.len());
        } else {
            state.records.push(Record {
                label,
                address,
                len: bytes.len(),
                freed: false,
                observation: None,
            });
        }
    });
}

pub(super) struct Probe;

impl Probe {
    pub(super) fn start() -> Self {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(!state.active, "one probe per test thread");
            state.records.clear();
            state.active = true;
        });
        Self
    }

    pub(super) fn finish(self) -> Report {
        let records = STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.active = false;
            std::mem::take(&mut state.records)
        });
        Report(records)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = STATE.try_with(|state| {
            let mut state = state.borrow_mut();
            state.active = false;
            state.records.clear();
        });
    }
}

pub(super) struct Report(Vec<Record>);

impl Report {
    pub(super) fn assert_wiped(&self, labels: &[&str]) {
        for label in labels {
            assert!(
                self.0.iter().any(|record| record.label == *label),
                "no initialized payload was registered for {label}: {:?}",
                self.0
            );
        }
        assert!(!self.0.is_empty(), "the probe must observe a payload");
        for record in &self.0 {
            assert!(
                record.freed,
                "payload destruction was not observed: {record:?}"
            );
            assert_eq!(
                record.observation,
                Some(Observation::Wiped),
                "the initialized payload must be wiped before deallocation: {record:?}"
            );
        }
    }

    pub(super) fn allocations(&self) -> usize {
        self.0.len()
    }

    pub(super) fn allocations_for(&self, label: &str) -> usize {
        self.0.iter().filter(|record| record.label == label).count()
    }
}

#[test]
fn an_unwiped_payload_is_detected_without_reading_its_spare_capacity() {
    let probe = Probe::start();
    let mut payload = Vec::with_capacity(16_384);
    payload.resize(8193, 0);
    payload[8192] = b'!';
    watch("control", &payload);

    drop(Vec::<u8>::with_capacity(8192));
    drop(payload);
    let report = probe.finish();
    assert_eq!(report.allocations(), 1);
    assert_eq!(report.allocations_for("control"), 1);
    assert!(report.0[0].freed, "the negative control was actually freed");
    assert_eq!(report.0[0].observation, Some(Observation::Unwiped));
}

#[test]
fn a_held_payload_is_wiped_before_its_matched_deallocation() {
    let probe = Probe::start();
    let mut payload = Vec::with_capacity(16_384);
    payload.resize(8193, b'!');
    watch("held control", &payload);
    drop(busbar_contract::abi::sdk::cred::Held::new(payload));
    let report = probe.finish();
    assert_eq!(report.allocations(), 1);
    assert_eq!(report.allocations_for("held control"), 1);
    report.assert_wiped(&["held control"]);
}

#[test]
fn a_live_payload_has_no_deallocation_receipt() {
    let probe = Probe::start();
    let payload = b"still owned".to_vec();
    watch("live", &payload);
    let report = probe.finish();
    assert_eq!(report.allocations(), 1);
    assert!(
        !report.0[0].freed,
        "registration is not a destruction receipt"
    );
    drop(payload);
}

impl Report {
    pub(super) fn assert_decoded_wiped(&self) {
        assert!(
            self.0
                .iter()
                .any(|record| matches!(record.label, "parser scratch" | "parsed value")),
            "the actual parser must expose initialized decoded payload custody"
        );
        self.assert_wiped(&["token", "response body"]);
    }
    pub(super) fn assert_unwiped(&self, label: &str) {
        assert!(
            self.0.iter().any(|record| record.label == label
                && record.freed
                && record.observation == Some(Observation::Unwiped)),
            "the real baseline decoder must expose an unwiped initialized payload: {:?}",
            self.0
        );
    }
}

#[test]
fn only_the_registered_prefix_is_examined() {
    let probe = Probe::start();
    let mut payload = vec![b'!'; 16384];
    payload[..8192].fill(0);
    watch("prefix", &payload[..8192]);
    // The tail is initialized so a faulty whole-allocation reader fails safely.
    drop(payload);
    probe.finish().assert_wiped(&["prefix"]);
}
