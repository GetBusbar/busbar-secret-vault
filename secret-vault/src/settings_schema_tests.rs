// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../testing/settings/integer_token.rs"]
mod settings_profile;

use busbar_contract::abi::sdk::life::Life;

#[test]
fn settings_schema_matches_lifecycle_shapes() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).expect("schema JSON");
    let validator = settings_profile::validator(&schema).expect("valid settings schema");
    let cases: &[(&str, bool)] = &[
        (
            r#"{"addr":"https://vault.example.test:8200","token":null}"#,
            true,
        ),
        (
            r#"{"addr":"http://localhost:8200/","token":{"env":"EXAMPLE_TOKEN"},"ca_cert_pem":null,"timeout_secs":1}"#,
            true,
        ),
        (
            r#"{"addr":"https://vault.example.test","token":false}"#,
            true,
        ),
        (r#"{}"#, false),
        (r#"null"#, false),
        (r#"[]"#, false),
        (r#"{"addr":"https://vault.example.test"}"#, false),
        (r#"{"token":null}"#, false),
        (
            r#"{"addr":"https://vault.example.test","token":null,"timeout_secs":0}"#,
            false,
        ),
        (
            r#"{"addr":"https://vault.example.test","token":null,"timeout_secs":null}"#,
            false,
        ),
        (
            r#"{"addr":"https://vault.example.test","token":null,"ca_cert_pem":7}"#,
            false,
        ),
        (
            r#"{"addr":"https://vault.example.test","token":null,"unknown":0}"#,
            false,
        ),
    ];
    for &(text, accepted) in cases {
        let value: serde_json::Value = serde_json::from_str(text).expect("case JSON");
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            super::Vault::validate(text.as_bytes()).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    assert!(!super::Vault::validate(b"").is_ok());
    // Semantic URL checks remain with the lifecycle parser.
    assert!(
        super::Vault::validate(br#"{"addr":"ftp://vault.example.test","token":null}"#).is_err()
    );
    assert!(
        super::Vault::validate(br#"{"addr":"https://vault.example.test?query","token":null}"#)
            .is_err()
    );
}

#[test]
fn settings_schema_marks_secret_fields_without_defaults() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).unwrap();
    let field = &schema["properties"]["token"];
    assert_eq!(field["writeOnly"], true);
    assert_eq!(field["x-busbar-secret"], true);
    assert!(field.get("default").is_none());
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("settings.schema.json")).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/properties/timeout_secs"#,
        r#"{"addr":"https://vault.example.test","token":null,"timeout_secs":TOKEN}"#,
        "1",
        "unsigned",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                super::Vault::validate(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                super::Vault::validate(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
