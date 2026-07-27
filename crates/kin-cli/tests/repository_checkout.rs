// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_cli::commands::checkout::parse_checkout_path;

#[test]
fn checkout_path_parser_is_byte_safe_component_aware_and_control_safe() {
    assert_eq!(
        parse_checkout_path(Some("src"), None).unwrap().as_bytes(),
        b"src"
    );
    assert_eq!(
        parse_checkout_path(None, Some("7372632fff"))
            .unwrap()
            .as_bytes(),
        b"src/\xff"
    );
    for (path, encoded, message) in [
        (None, None, "provide"),
        (Some("src"), Some("737263"), "either"),
        (Some(""), None, "must not be empty"),
        (Some("../src"), None, "must not contain"),
        (Some("/src"), None, "must be relative"),
        (Some(".kin/config"), None, "reserved"),
        (Some(".git/config"), None, "reserved"),
    ] {
        let error = parse_checkout_path(path, encoded).expect_err("path must fail");
        assert!(error.to_string().contains(message), "{error}");
    }
    assert!(parse_checkout_path(None, Some("7372632FFF"))
        .unwrap_err()
        .to_string()
        .contains("canonical lowercase"));
    assert!(parse_checkout_path(None, Some("zz"))
        .unwrap_err()
        .to_string()
        .contains("invalid repository path hex"));
}
