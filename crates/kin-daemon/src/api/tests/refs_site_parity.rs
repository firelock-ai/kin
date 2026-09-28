// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// `kin refs` through the daemon and `find_references` over MCP address one
/// call site the same way: the caller by its id and the file it is projected
/// into, the site as its line inside the caller and the text at it, cut from
/// the caller's own body. Neither carries a file line.
#[tokio::test]
async fn refs_and_find_references_address_a_site_inside_its_caller_alike() {
    let (_repo, state) = refs_source_observation_fixture().await;
    let focal = waiting_entity(&state, "local.py", "work");
    let caller = waiting_entity(&state, "caller.py", "run");

    let mcp = mcp_call(
        router(Arc::clone(&state)),
        "find_references",
        json!({"entity_id": focal.id.to_string(), "relation_kinds": ["calls"]}),
    )
    .await;
    assert_ne!(mcp.is_error, Some(true), "{}", mcp_result_text(&mcp));
    let payload = tool_result_payload(&mcp);
    let row = payload["references"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["name"] == "run"))
        .unwrap_or_else(|| panic!("no row for the caller: {payload:#}"));
    assert_eq!(row["entity_id"], caller.id.to_string(), "{row:#}");
    assert_eq!(row["projection"], json!({"path": "caller.py"}), "{row:#}");
    // `run` starts on the file's third line and calls `work` on the next one.
    assert_eq!(
        row["sites"],
        json!([{"line_in_entity": 1, "callee": "work"}]),
        "{row:#}"
    );
    assert_eq!(row["site_count"], 1, "{row:#}");
    for gone in ["file_path", "start_line", "reference_lines"] {
        assert!(row.get(gone).is_none(), "{gone}: {row:#}");
    }

    let cli = refs_calls_through_route(&state, &focal.id.to_string()).await;
    let text = cli.lines.join("\n");
    let printed = cli
        .lines
        .iter()
        .find(|line| line.starts_with("  run ["))
        .unwrap_or_else(|| panic!("no row for the caller: {text}"));
    assert!(
        printed.starts_with(&format!(
            "  run [{}] (projection: caller.py) [Calls]",
            caller.id
        )),
        "{text}"
    );
    assert!(
        printed.ends_with("sites +1 `work`"),
        "the CLI prints the site MCP serves: {text}"
    );
    // A file line is a path followed by `:` and a line number. The call-site
    // summary names the focal's file before a colon of its own ("files that
    // import local.py: 0 across 2 callers"), which is prose and not a line.
    let file_line = |path: &str| {
        text.match_indices(&format!("{path}:"))
            .any(|(at, found)| text[at + found.len()..].starts_with(|c: char| c.is_ascii_digit()))
    };
    assert!(
        !file_line("caller.py") && !file_line("local.py"),
        "no file line reaches the answer: {text}"
    );
}
