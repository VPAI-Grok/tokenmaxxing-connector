//! Boundary tests for the published UsageSnapshotV1 JSON Schema.

use regex::Regex;
use serde_json::Value;

fn decimal_patterns() -> Vec<Regex> {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/usage-snapshot-v1.schema.json"))
            .unwrap_or_else(|_| panic!("snapshot schema must parse"));
    schema["$defs"]["decimal"]["oneOf"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|branch| branch["pattern"].as_str())
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect()
}

fn schema_accepts_decimal(patterns: &[Regex], value: &str) -> bool {
    patterns.iter().any(|pattern| pattern.is_match(value))
}

#[test]
fn decimal_schema_matches_postgresql_bigint_boundaries() {
    let patterns = decimal_patterns();
    assert_eq!(patterns.len(), 2, "both decimal branches must compile");
    for accepted in [
        "0",
        "1",
        "999999999999999999",
        "1000000000000000000",
        "9000000000000000000",
        "9223372036854775806",
        "9223372036854775807",
    ] {
        assert!(
            schema_accepts_decimal(&patterns, accepted),
            "must accept {accepted}"
        );
    }
    for rejected in [
        "",
        "00",
        "01",
        "-1",
        "9223372036854775808",
        "9999999999999999999",
        "18446744073709551615",
    ] {
        assert!(
            !schema_accepts_decimal(&patterns, rejected),
            "must reject {rejected}"
        );
    }

    // Deterministically exercise values across the full u64 range so a typo
    // in one of the 19-digit prefix branches cannot silently narrow or widen
    // the PostgreSQL bigint boundary.
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    for _ in 0..4_096 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let accepted = state & (i64::MAX as u64);
        let rejected = (i64::MAX as u64 + 1).saturating_add(accepted);
        assert!(schema_accepts_decimal(&patterns, &accepted.to_string()));
        assert!(!schema_accepts_decimal(&patterns, &rejected.to_string()));
    }
}
