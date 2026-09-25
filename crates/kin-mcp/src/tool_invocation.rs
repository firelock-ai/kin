// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Expand a discovered tool call before the normal dispatch boundary.

use std::collections::HashSet;

use crate::error::{McpError, Result};
use crate::types::ToolCallParams;

pub const TOOL_NAME: &str = "kin_tool_call";
pub const DESCRIPTION: &str = "Invoke a read-only tool found through kin_tool_search. Pass its exact name in tool and its input object in arguments. Mutating tools require a direct call through a profile that serves them; normal authorization still applies.";

pub fn enabled(allowed: Option<&HashSet<String>>) -> bool {
    allowed.is_none_or(|names| names.contains(TOOL_NAME))
}

/// Only an explicitly served dispatcher can expand a hidden registered name.
/// The returned target still uses the ordinary defaults, authority checks,
/// response envelope and persistence path; discovery changes no connection state.
pub fn expand(call: &mut ToolCallParams, allowed: Option<&HashSet<String>>) -> Result<bool> {
    if call.name != TOOL_NAME {
        return Ok(false);
    }
    if !enabled(allowed) {
        return Err(McpError::InvalidParams(format!(
            "tool '{TOOL_NAME}' is not enabled in this MCP profile"
        )));
    }
    if call
        .arguments
        .keys()
        .any(|key| key != "tool" && key != "arguments")
    {
        return Err(McpError::InvalidParams(
            "kin_tool_call accepts only tool and arguments".into(),
        ));
    }
    let mut name = call
        .arguments
        .get("tool")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("kin_tool_call requires a tool name".into()))?
        .to_owned();
    crate::agent_belt::canonicalize_tool_name(&mut name);
    if name == TOOL_NAME || name == crate::handlers::tool_search::TOOL_NAME {
        return Err(McpError::InvalidParams(
            "call kin_tool_search directly; recursive tool dispatch is not supported".into(),
        ));
    }
    let registry = crate::tools::tool_definitions();
    let target = registry
        .tools
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| McpError::InvalidParams(format!("unknown discovered tool '{name}'")))?;
    if !target.annotations.read_only_hint {
        return Err(McpError::InvalidParams(format!(
            "kin_tool_call is read-only; '{name}' requires a direct call through a profile that serves it"
        )));
    }
    let arguments = call
        .arguments
        .get("arguments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            McpError::InvalidParams("kin_tool_call requires an arguments object".into())
        })?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    call.name = name;
    call.arguments = arguments;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discovered_call_refuses_disabled_unknown_recursive_and_malformed_inputs() {
        let valid = json!({"name": TOOL_NAME, "arguments": {"tool": "semantic_search", "arguments": {"query": "Widget"}}});
        let disabled = HashSet::from(["kin_tool_search".to_string()]);
        assert!(expand(
            &mut serde_json::from_value(valid.clone()).unwrap(),
            Some(&disabled)
        )
        .is_err());
        for args in [
            json!({}),
            json!({"tool": "not_a_tool", "arguments": {}}),
            json!({"tool": TOOL_NAME, "arguments": {}}),
            json!({"tool": "kin_tool_search", "arguments": {}}),
            json!({"tool": "semantic_search", "arguments": []}),
            json!({"tool": "semantic_search", "arguments": {}, "session_id": "outer-injection"}),
        ] {
            let mut call =
                serde_json::from_value(json!({"name": TOOL_NAME,"arguments": args})).unwrap();
            assert!(expand(&mut call, None).is_err());
        }
        for tool in crate::tools::tool_definitions()
            .tools
            .into_iter()
            .filter(|tool| !tool.annotations.read_only_hint)
        {
            let mut call = serde_json::from_value(
                json!({"name": TOOL_NAME,"arguments":{"tool":tool.name,"arguments":{}}}),
            )
            .unwrap();
            assert!(expand(&mut call, None)
                .unwrap_err()
                .to_string()
                .contains("read-only"));
        }
        let mut call = serde_json::from_value(valid).unwrap();
        assert!(expand(&mut call, None).unwrap());
        assert_eq!(call.name, "semantic_search");
        assert_eq!(call.arguments["query"], "Widget");
    }
}
