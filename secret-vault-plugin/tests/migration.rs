// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::migrate::{MigrateNeed, Migrated};
use busbar_plugin_loader::dispatch::load::raw;
use busbar_plugin_loader::dispatch::migrate::{migrate_door, migrate_library};
use serde_json::{json, Value};

const CANARY: &str = "vault-migration-secret-${DO_NOT_EXPAND}-canary";

fn assert_migration_contract(migrate: impl Fn(&Value, &str) -> Migrated) {
    let old = json!({
        "addr": "https://vault.example.test:8200",
        "token": CANARY,
        "timeout_secs": 10
    });
    for from in ["1.5.5", "v1.5.5", "1.4.2"] {
        let first = migrate(&old, from);
        assert_eq!(
            first.settings, old,
            "no invented reference or changed credential"
        );
        assert_eq!(
            first.needs,
            vec![MigrateNeed::ExternalizeSecret {
                path: vec!["token".into()]
            }]
        );
        let serialized_needs = serde_json::to_string(&first.needs).unwrap();
        assert!(!serialized_needs.contains(CANARY));
        assert_eq!(first.report.len(), 1);
        let report = &first.report[0];
        assert!(report.contains("settings.token"));
        assert!(report.contains("secure-file extraction"));
        assert!(!report.contains(CANARY) && !report.contains("DO_NOT_EXPAND"));
        let repeated = migrate(&first.settings, from);
        assert_eq!(
            repeated, first,
            "unconsumed extraction need is stable on repeated migration"
        );
    }
    for from in [
        "1.6.0", "1.7.0", "2.0.0", "", "unknown", "1.5.bad", "1.5.5.1",
    ] {
        assert_eq!(migrate(&old, from), Migrated::unchanged(old.clone()));
    }
    for token in [
        json!({"env":"VAULT_TOKEN"}),
        json!({"file":"/run/secrets/vault-token"}),
        json!({"module":"env","settings":{"key":"VAULT_TOKEN"}}),
        json!(null),
        json!(false),
        json!(17),
    ] {
        let settings = json!({"addr":"https://vault.example.test", "token":token});
        assert_eq!(migrate(&settings, "1.5.5"), Migrated::unchanged(settings));
    }
    for settings in [json!(null), json!({}), json!([])] {
        assert_eq!(migrate(&settings, "1.5.5"), Migrated::unchanged(settings));
    }
}

#[test]
fn linked_vault_migration_requests_literal_extraction_without_exposing_it() {
    assert_migration_contract(|settings, from| {
        migrate_door(raw(busbar_secret_vault::door::door), settings, from)
            .expect("actual linked Vault migration answers")
            .expect("actual Vault door declares MIGRATE")
    });
}

#[test]
fn dropped_vault_migration_requests_literal_extraction_without_exposing_it() {
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("BUSBAR_PLUGIN_CDYLIB must name the freshly built actual Vault image"),
    );
    assert!(path.is_absolute() && path.is_file());
    let bytes = std::fs::read(&path).expect("actual Vault image is readable");
    assert_migration_contract(|settings, from| {
        migrate_library(&bytes, "actual-vault-migration-image", settings, from)
            .expect("actual dropped Vault migration answers")
            .expect("actual Vault image declares MIGRATE")
    });
}
