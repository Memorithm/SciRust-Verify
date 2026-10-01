use super::*;

#[test]
fn read_budget_rejects_file_count_and_byte_overflow() {
    let mut count_budget = ReadBudget {
        files: MAX_BUNDLE_FILES,
        bytes: 0,
    };
    assert!(matches!(
        count_budget.account("run-test", "extra", 0),
        Err(StoreError::Corrupt { .. })
    ));

    let mut byte_budget = ReadBudget {
        files: 0,
        bytes: MAX_BUNDLE_BYTES,
    };
    assert!(matches!(
        byte_budget.account("run-test", "extra", 1),
        Err(StoreError::Corrupt { .. })
    ));

    let mut file_budget = ReadBudget::default();
    assert!(matches!(
        file_budget.account("run-test", "huge", MAX_BUNDLE_FILE_BYTES + 1),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn path_policy_rejects_absolute_traversal_and_excessive_depth() {
    for invalid in [
        "../../escape",
        "/absolute",
        "C:/absolute",
        "a\\..\\escape",
        "a//b",
        "./a",
    ] {
        assert!(matches!(
            sanitize_attachment_path(invalid),
            Err(StoreError::Corrupt { .. })
        ));
    }

    let too_deep = std::iter::repeat_n("d", MAX_BUNDLE_DEPTH + 1)
        .collect::<Vec<_>>()
        .join("/");
    assert!(matches!(
        sanitize_attachment_path(&too_deep),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn run_id_policy_rejects_paths_and_malformed_ids() {
    for invalid in [
        "../../outside",
        "/tmp/run-20260101T000000Z-12345678",
        "run-20260101T000000Z-ABCDEF12",
        "run-20260101T000000Z-1234567",
    ] {
        assert!(matches!(
            validate_run_id(invalid),
            Err(StoreError::Corrupt { .. })
        ));
    }
    assert!(validate_run_id("run-20260101T000000Z-1234abcd").is_ok());
}
