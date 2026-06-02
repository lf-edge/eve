// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::tcg::tcg_tpmlog::TcgTpmLog;

fn get_test_data_path(data: &str) -> std::path::PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("Failed to find CARGO_MANIFEST_DIR");
    let test_data_path = std::path::Path::new(&manifest_dir).join("test_data");
    test_data_path.join(data)
}

#[test]
fn test_tcg_log_from_slice() {
    let data = std::fs::read(get_test_data_path("tcg/tcg_log_1")).unwrap();
    let log = TcgTpmLog::from_slice(&data);
    assert!(log.is_ok());
}
