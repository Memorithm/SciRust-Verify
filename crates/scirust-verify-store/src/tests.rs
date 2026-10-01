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

    let mut directory_budget = ReadBudget {
        files: MAX_BUNDLE_FILES,
        bytes: 0,
    };
    assert!(matches!(
        directory_budget.account_entry("run-test"),
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
fn traversal_rejects_a_file_beyond_the_component_depth_limit() {
    let root = std::env::temp_dir().join(format!(
        "svs-depth-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    let mut directory = store.path().to_path_buf();
    for index in 0..MAX_BUNDLE_DEPTH {
        directory.push(format!("d{index}"));
    }
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("leaf.bin"), b"leaf").unwrap();

    let mut budget = ReadBudget::default();
    let mut files = BTreeMap::new();
    assert!(matches!(
        store.collect_files(store.path(), 0, &mut budget, &mut files, None),
        Err(StoreError::Corrupt { reason, .. }) if reason.contains("component-depth")
    ));
    fs::remove_dir_all(root).unwrap();
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
