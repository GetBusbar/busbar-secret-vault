// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, Dispatcher, LinkedRow, NoSink,
};
use std::sync::Arc;
fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("vault-metadata"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    }
}
// These negative inputs retain this product's actual Statement and operation table. Only the
// numerical ABI/layout declaration or version string is changed; no plugin behavior is copied.
extern "C" fn metadata_door<const CASE: usize>(
) -> *const busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    static DOORS: [std::sync::OnceLock<usize>; 5] = [const { std::sync::OnceLock::new() }; 5];
    *DOORS[CASE].get_or_init(|| {
        let mut parts = busbar_secret_vault::door::door().parts();
        let kind = busbar_contract::abi::mechanism::KindCode::Secret;
        match CASE {
            0 => parts.kind_abi = kind.abi_version() + 1,
            1 => parts.kind_abi = kind.abi_version().wrapping_sub(1),
            2 => parts.layout = kind.layout_fingerprint() ^ 1,
            3 => parts.layout = 0,
            4 => {
                // SAFETY: the actual product's immutable Statement and all nested ranges are static.
                let statement = unsafe { parts.statement.read_unaligned() };
                const OTHER: &str = "0.0.0-conformance-restated";
                parts.statement = Box::leak(Box::new(Statement {
                    version: busbar_contract::abi::mechanism::call::AbiStr {
                        ptr: OTHER.as_ptr(),
                        len: OTHER.len(),
                    },
                    ..statement
                }));
            }
            _ => unreachable!(),
        }
        // SAFETY: the actual product's full table and nested Statement ranges remain immutable
        // and static. Changed metadata is deliberately invalid and judged before any operation.
        let door = unsafe { Door::__from_parts(parts) };
        Box::into_raw(Box::new(door)) as usize
    }) as *const Door
}

fn metadata_image() -> std::path::PathBuf {
    let image = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("BUSBAR_PLUGIN_CDYLIB must name the freshly built actual image"),
    );
    assert!(image.is_absolute() && image.is_file());
    image
}

#[test]
fn the_actual_kind_abi_is_checked_by_pack_linked_and_dropped_origins() {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use busbar_plugin_loader::dispatch::LoadError;
    let kind = busbar_contract::abi::mechanism::KindCode::Secret;
    let host = kind.abi_version();
    assert_eq!(busbar_secret_vault::door::door().parts().kind_abi, host);
    let d = Dispatcher::new(Default::default());
    let honest = LinkedRow::of(busbar_secret_vault::door::door).expect("actual Statement");
    let _ = load_linked::<Secret>(&honest, bind(&d)).expect("honest linked twin");
    let _ = load_dropped::<Secret>(&metadata_image(), &honest.statement, bind(&d))
        .expect("honest dropped twin");
    for (door, abi) in [
        (metadata_door::<0> as RawDoorFn, host + 1),
        (metadata_door::<1>, host.wrapping_sub(1)),
    ] {
        let want = LoadError::KindAbi {
            kind,
            door: abi,
            host,
        };
        let packed = busbar_plugin_loader::dispatch::load::rendering_of_raw(door)
            .expect_err("pack refuses another ABI");
        assert_eq!(packed, want);
        let linked = LinkedRow::of_raw(door)
            .and_then(|row| load_linked::<Secret>(&row, bind(&d)).map(|_| ()))
            .expect_err("linked refuses another ABI");
        assert_eq!(linked, want);
        assert!(linked.to_string().contains("rebuild"));
        let mut statement = honest.statement.clone();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        statement[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Secret>(&metadata_image(), &statement, bind(&d))
                .map(|_| ())
                .err(),
            Some(LoadError::ManifestKindAbi { stated: abi, host })
        );
    }
}

#[test]
fn the_actual_kind_layout_is_checked_under_honest_and_own_rows() {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use busbar_plugin_loader::dispatch::LoadError;
    let kind = busbar_contract::abi::mechanism::KindCode::Secret;
    let host = kind.layout_fingerprint();
    assert_eq!(busbar_secret_vault::door::door().parts().layout, host);
    let d = Dispatcher::new(Default::default());
    let honest = LinkedRow::of(busbar_secret_vault::door::door).unwrap();
    let _ = load_linked::<Secret>(&honest, bind(&d)).unwrap();
    let _ = load_dropped::<Secret>(&metadata_image(), &honest.statement, bind(&d)).unwrap();
    for (door, stated) in [
        (metadata_door::<2> as RawDoorFn, host ^ 1),
        (metadata_door::<3>, 0),
    ] {
        let refusal = busbar_plugin_loader::dispatch::load::rendering_of_raw(door)
            .expect_err("pack refuses incompatible layout");
        let LoadError::KindLayout {
            kind: named,
            stated: said,
            host: read,
            ..
        } = &refusal
        else {
            panic!("{refusal:?}")
        };
        assert_eq!((*named, *said, *read), (kind, stated, host));
        assert!(refusal
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let row = LinkedRow {
            statement: honest.statement.clone(),
            door,
        };
        assert_eq!(
            load_linked::<Secret>(&row, bind(&d)).map(|_| ()).err(),
            Some(refusal.clone())
        );
        assert_eq!(
            LinkedRow::of_raw(door)
                .and_then(|row| load_linked::<Secret>(&row, bind(&d)).map(|_| ()))
                .err(),
            Some(refusal)
        );
    }
}

#[test]
fn the_actual_statement_matches_each_row_manifest_and_restated_version() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(Default::default());
    let honest = LinkedRow::of(busbar_secret_vault::door::door).unwrap();
    let _ = load_linked::<Secret>(&honest, bind(&d)).unwrap();
    let _ = load_dropped::<Secret>(&metadata_image(), &honest.statement, bind(&d)).unwrap();
    let mut changed = honest.statement.clone();
    let version = busbar_contract::abi::mechanism::rendering::read(&changed)
        .unwrap()
        .version;
    let at = changed
        .windows(version.len())
        .position(|bytes| bytes == version.as_bytes())
        .unwrap();
    changed[at + version.len() - 1] ^= 1;
    let read = busbar_contract::abi::mechanism::rendering::read(&changed)
        .expect("metadata mismatch must remain a valid rendering");
    assert_ne!(read.version, version);
    let row = LinkedRow {
        statement: changed.clone(),
        door: honest.door,
    };
    assert_eq!(
        load_linked::<Secret>(&row, bind(&d)).map(|_| ()).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Secret>(&metadata_image(), &changed, bind(&d))
            .map(|_| ())
            .err(),
        Some(LoadError::StatementMismatch)
    );
    let row = LinkedRow {
        statement: honest.statement,
        door: metadata_door::<4>,
    };
    assert_eq!(
        load_linked::<Secret>(&row, bind(&d)).map(|_| ()).err(),
        Some(LoadError::StatementMismatch)
    );
}

fn other_kind_is_refused<K: busbar_plugin_loader::dispatch::Kind>() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(Default::default());
    let row = LinkedRow::of(busbar_secret_vault::door::door).unwrap();
    let want = LoadError::ManifestKind {
        stated: busbar_contract::abi::mechanism::KindCode::Secret,
        want: K::CODE,
    };
    assert_eq!(
        load_linked::<K>(&row, bind(&d)).map(|_| ()).err(),
        Some(want.clone())
    );
    assert_eq!(
        load_dropped::<K>(&metadata_image(), &row.statement, bind(&d))
            .map(|_| ())
            .err(),
        Some(want)
    );
}

#[test]
fn the_actual_image_is_refused_as_every_other_kind_through_both_origins() {
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::auth::Auth>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::export::Export>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::hook::Hook>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::plane::Plane>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::store::Store>();
    other_kind_is_refused::<busbar_plugin_loader::dispatch::kinds::transport::Transport>();
}

#[test]
fn the_actual_dropped_image_is_physically_distinct_from_the_linked_image() {
    let (door, ops) =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&metadata_image())
            .unwrap()
            .unwrap();
    let linked = busbar_secret_vault::door::door();
    assert_ne!(door, std::ptr::from_ref(linked) as usize);
    assert_ne!(ops, linked.parts().ops as usize);
}
