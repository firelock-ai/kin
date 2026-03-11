//! Hook template generation for assistant CLIs.
//!
//! Generates recommended hook configurations that remind coding agents
//! to use Kin tools instead of raw file operations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookTemplate {
    pub event: String,
    pub matcher: Option<String>,
    pub command: String,
    pub description: String,
}

/// Generate recommended Claude Code hook templates.
///
/// Returns hooks that remind the agent to use Kin CLI commands
/// for semantic operations instead of raw file manipulation.
pub fn generate_claude_hooks() -> Vec<HookTemplate> {
    vec![
        HookTemplate {
            event: "PreToolUse".into(),
            matcher: Some("Edit|Write".into()),
            command: "echo '⚠ This repo uses Kin. Before editing, run `kin review` to check semantic impact and `kin context <entity>` to understand the entity you are modifying.'".into(),
            description: "Reminds the agent to run `kin review` and `kin context <entity>` before editing files.".into(),
        },
        HookTemplate {
            event: "PostToolUse".into(),
            matcher: Some("Bash".into()),
            command: r#"if echo "$TOOL_INPUT" | grep -q 'git commit'; then echo '⚠ Use `kin commit` instead of `git commit` to preserve semantic history.'; fi"#.into(),
            description: "Reminds the agent to use `kin commit` instead of `git commit` for semantic tracking.".into(),
        },
        HookTemplate {
            event: "SessionStart".into(),
            matcher: None,
            command: "echo '📋 This repo uses Kin (semantic VCS). Start with `kin support` to understand coverage. Use `kin search <query>` for semantic search. Use `kin context <entity>` for focused context. Use `kin commit` to record changes.'".into(),
            description: "Orients the agent to Kin workflows at the start of each session.".into(),
        },
    ]
}

/// Render hook templates as Claude Code settings.json hooks format.
pub fn render_hooks_json(hooks: &[HookTemplate]) -> String {
    let mut events: std::collections::BTreeMap<&str, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();

    for hook in hooks {
        let hook_entry = serde_json::json!({
            "type": "command",
            "command": hook.command,
        });

        let entry = if let Some(ref matcher) = hook.matcher {
            serde_json::json!({
                "matcher": matcher,
                "hooks": [hook_entry],
            })
        } else {
            serde_json::json!({
                "hooks": [hook_entry],
            })
        };

        events.entry(&hook.event).or_default().push(entry);
    }

    let hooks_obj: serde_json::Map<String, serde_json::Value> = events
        .into_iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::Array(v)))
        .collect();

    let root = serde_json::json!({ "hooks": hooks_obj });
    serde_json::to_string_pretty(&root).expect("hook templates are always serializable")
}

/// Render a human-readable setup guide for the hook templates.
pub fn render_hooks_instructions(hooks: &[HookTemplate]) -> String {
    let mut out = String::new();
    out.push_str("# Kin — Claude Code Hook Setup Guide\n\n");
    out.push_str(
        "Add these hooks to your `.claude/settings.json` to get Kin-aware reminders.\n\n",
    );

    for (i, hook) in hooks.iter().enumerate() {
        out.push_str(&format!("## Hook {} — {} ", i + 1, hook.event));
        if let Some(ref m) = hook.matcher {
            out.push_str(&format!("(matcher: {})", m));
        }
        out.push('\n');
        out.push_str(&format!("  {}\n\n", hook.description));
    }

    out.push_str("## Quick Start\n\n");
    out.push_str("1. Copy the JSON output from `kin assistant hooks claude-code`.\n");
    out.push_str("2. Merge the `hooks` object into your `.claude/settings.json`.\n");
    out.push_str("3. Key Kin CLI commands the hooks reference:\n");
    out.push_str("   - `kin search <query>` — semantic search across the codebase\n");
    out.push_str("   - `kin context <entity>` — focused context for an entity\n");
    out.push_str("   - `kin commit` — record a semantic change\n");
    out.push_str("   - `kin review` — review semantic impact before editing\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_claude_hooks_count() {
        let hooks = generate_claude_hooks();
        assert_eq!(hooks.len(), 3, "expected 3 hook templates");
    }

    #[test]
    fn test_render_hooks_json_valid() {
        let hooks = generate_claude_hooks();
        let json_str = render_hooks_json(&hooks);
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("render_hooks_json must produce valid JSON");
        assert!(parsed.get("hooks").is_some(), "root must contain 'hooks' key");
        let hooks_obj = parsed["hooks"].as_object().unwrap();
        assert!(hooks_obj.contains_key("PreToolUse"));
        assert!(hooks_obj.contains_key("PostToolUse"));
        assert!(hooks_obj.contains_key("SessionStart"));
    }

    #[test]
    fn test_hooks_mention_kin_commands() {
        let hooks = generate_claude_hooks();
        let instructions = render_hooks_instructions(&hooks);
        assert!(instructions.contains("kin search"), "must mention kin search");
        assert!(instructions.contains("kin context"), "must mention kin context");
        assert!(instructions.contains("kin commit"), "must mention kin commit");
        assert!(instructions.contains("kin review"), "must mention kin review");
    }
}
