use kinetix_plugin_sdk::health::kinetix::plugin::types::{
    HealthObservationV2, QuotaScopeV1, QuotaSnapshotV1,
};

#[test]
fn distinguishes_unknown_zero_and_full_quota() {
    let unknown = QuotaSnapshotV1 {
        scope: QuotaScopeV1::Account,
        remaining_fraction: None,
        remaining: None,
        limit: None,
        unit: None,
        window: None,
        reset_at: None,
    };
    let exhausted = QuotaSnapshotV1 {
        remaining_fraction: Some(0.0),
        ..unknown.clone()
    };
    let full = QuotaSnapshotV1 {
        remaining_fraction: Some(1.0),
        ..unknown.clone()
    };

    assert_eq!(unknown.remaining_fraction, None);
    assert_eq!(exhausted.remaining_fraction, Some(0.0));
    assert_eq!(full.remaining_fraction, Some(1.0));
}

#[test]
fn represents_multiple_windows_and_model_scoped_quota() {
    let observation = HealthObservationV2 {
        state: "healthy".into(),
        quota_state: None,
        reset_at: None,
        retry_after: None,
        detail_code: None,
        quota_snapshots: vec![
            QuotaSnapshotV1 {
                scope: QuotaScopeV1::Account,
                remaining_fraction: Some(0.72),
                remaining: Some(720),
                limit: Some(1_000),
                unit: Some("requests".into()),
                window: Some("5h".into()),
                reset_at: None,
            },
            QuotaSnapshotV1 {
                scope: QuotaScopeV1::Model("gemini-2.5-pro".into()),
                remaining_fraction: Some(0.4),
                remaining: None,
                limit: None,
                unit: Some("tokens".into()),
                window: Some("daily".into()),
                reset_at: Some("2026-04-01T00:00:00Z".into()),
            },
            QuotaSnapshotV1 {
                scope: QuotaScopeV1::Unknown,
                remaining_fraction: Some(0.15),
                remaining: None,
                limit: None,
                unit: None,
                window: None,
                reset_at: None,
            },
        ],
    };

    assert_eq!(observation.quota_snapshots.len(), 3);
    assert!(matches!(
        observation.quota_snapshots[0].scope,
        QuotaScopeV1::Account
    ));
    assert!(matches!(
        &observation.quota_snapshots[1].scope,
        QuotaScopeV1::Model(model) if model == "gemini-2.5-pro"
    ));
    assert!(matches!(
        &observation.quota_snapshots[2].scope,
        QuotaScopeV1::Unknown
    ));
}

#[test]
fn no_quota_is_an_empty_snapshot_list() {
    let observation = HealthObservationV2 {
        state: "unknown".into(),
        quota_state: None,
        reset_at: None,
        retry_after: None,
        detail_code: None,
        quota_snapshots: Vec::new(),
    };

    assert!(observation.quota_snapshots.is_empty());
}
