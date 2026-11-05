// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One-shot upgrade requests for Vault settings. Runtime token handling remains reference-only.

use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated};

pub(crate) struct VaultMigration;

impl Migrate for VaultMigration {
    fn migrate(settings: serde_json::Value, from: &str) -> Migrated {
        let mut migrated = Migrated::unchanged(settings);
        if before_reference_only_tokens(from)
            && migrated
                .settings
                .get(crate::TOKEN_KEY)
                .is_some_and(serde_json::Value::is_string)
        {
            migrated.needs.push(MigrateNeed::ExternalizeSecret {
                path: vec![crate::TOKEN_KEY.to_string()],
            });
            migrated.report.push(
                "settings.token: requested secure-file extraction of the old inline credential; \
                 the credential value is withheld from this report."
                    .to_string(),
            );
        }
        migrated
    }
}

fn before_reference_only_tokens(from: &str) -> bool {
    let version = from.strip_prefix('v').unwrap_or(from);
    let version = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts = version.split('.');
    let parsed = (
        parts.next().and_then(|n| n.parse::<u64>().ok()),
        parts.next().and_then(|n| n.parse::<u64>().ok()),
        parts.next().and_then(|n| n.parse::<u64>().ok()),
    );
    matches!(parsed, (Some(1), Some(minor), Some(_)) if minor < 6) && parts.next().is_none()
}
