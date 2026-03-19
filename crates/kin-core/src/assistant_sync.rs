// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! Managed assistant-doc sync for AGENTS.md, CLAUDE.md, CODEX.md, GEMINI.md, etc.
//!
//! Writes Kin-generated content inside managed blocks while preserving all
//! user-authored content outside those blocks.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{KinError, Result};
use crate::layout::KinLayout;

// ---------------------------------------------------------------------------
// Managed block markers
// ---------------------------------------------------------------------------

const BLOCK_BEGIN: &str = "<!-- kin:begin -->";
const BLOCK_END: &str = "<!-- kin:end -->";

// ---------------------------------------------------------------------------
// Config model
// ---------------------------------------------------------------------------

/// Sync mode for managed assistant docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SyncMode {
    /// Only sync when `kin assistant sync` is run manually.
    #[default]
    Manual,
    /// Sync automatically on every `kin commit`.
    OnCommit,
    /// Sync via the daemon's auto-index loop.
    DaemonAuto,
}


impl std::fmt::Display for SyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manual => write!(f, "manual"),
            Self::OnCommit => write!(f, "on-commit"),
            Self::DaemonAuto => write!(f, "daemon-auto"),
        }
    }
}

/// Configuration for a single managed doc target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedDocTarget {
    /// Relative path from the repo root (e.g., "AGENTS.md", "CLAUDE.md").
    pub path: String,
    /// Whether this target is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Template policy: which sections to include in managed blocks.
    #[serde(default)]
    pub sections: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Top-level configuration for managed assistant doc sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedDocConfig {
    /// Global sync mode.
    #[serde(default)]
    pub sync_mode: SyncMode,
    /// Per-file targets.
    #[serde(default)]
    pub targets: Vec<ManagedDocTarget>,
}

impl Default for ManagedDocConfig {
    fn default() -> Self {
        Self {
            sync_mode: SyncMode::Manual,
            targets: vec![
                ManagedDocTarget {
                    path: "AGENTS.md".into(),
                    enabled: true,
                    sections: vec![
                        "summary".into(),
                        "kin-first".into(),
                        "conventions".into(),
                        "verification".into(),
                    ],
                },
                ManagedDocTarget {
                    path: "CLAUDE.md".into(),
                    enabled: false,
                    sections: vec![
                        "summary".into(),
                        "kin-first".into(),
                        "conventions".into(),
                        "bootstrap".into(),
                    ],
                },
                ManagedDocTarget {
                    path: "CODEX.md".into(),
                    enabled: false,
                    sections: vec![
                        "summary".into(),
                        "kin-first".into(),
                        "conventions".into(),
                        "bootstrap".into(),
                    ],
                },
                ManagedDocTarget {
                    path: "GEMINI.md".into(),
                    enabled: false,
                    sections: vec![
                        "summary".into(),
                        "kin-first".into(),
                        "conventions".into(),
                        "bootstrap".into(),
                    ],
                },
                ManagedDocTarget {
                    path: "copilot-instructions.md".into(),
                    enabled: false,
                    sections: vec!["summary".into(), "conventions".into()],
                },
            ],
        }
    }
}

impl ManagedDocConfig {
    /// Load config from `.kin/assistant-sync.toml`.
    pub fn load(layout: &KinLayout) -> Result<Self> {
        let path = Self::config_path(layout);
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path).map_err(|e| KinError::io(&path, e))?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save config to `.kin/assistant-sync.toml`.
    pub fn save(&self, layout: &KinLayout) -> Result<()> {
        let path = Self::config_path(layout);
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(&path, contents).map_err(|e| KinError::io(&path, e))?;
        Ok(())
    }

    /// Path to the config file.
    pub fn config_path(layout: &KinLayout) -> PathBuf {
        layout.root().join("assistant-sync.toml")
    }

    /// Return only enabled targets.
    pub fn enabled_targets(&self) -> Vec<&ManagedDocTarget> {
        self.targets.iter().filter(|t| t.enabled).collect()
    }
}

// ---------------------------------------------------------------------------
// Managed block parsing and writing
// ---------------------------------------------------------------------------

/// Split a file's content into segments: user content and managed blocks.
///
/// Returns a list of segments in order. User segments are preserved verbatim.
/// Managed block content (between markers) is replaced during sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// User-authored content — never modified.
    User(String),
    /// Managed block content — will be replaced on sync.
    Managed(String),
}

/// Parse a file into segments, separating user content from managed blocks.
pub fn parse_segments(content: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut remaining = content;

    loop {
        if let Some(begin_pos) = remaining.find(BLOCK_BEGIN) {
            // User content before the managed block
            let user_part = &remaining[..begin_pos];
            if !user_part.is_empty() {
                segments.push(Segment::User(user_part.to_string()));
            }

            let after_begin = &remaining[begin_pos + BLOCK_BEGIN.len()..];

            if let Some(end_pos) = after_begin.find(BLOCK_END) {
                // Managed content between begin and end markers
                let managed_part = &after_begin[..end_pos];
                segments.push(Segment::Managed(managed_part.to_string()));
                remaining = &after_begin[end_pos + BLOCK_END.len()..];
            } else {
                // Unclosed managed block — treat rest as managed
                segments.push(Segment::Managed(after_begin.to_string()));
                break;
            }
        } else {
            // No more managed blocks — rest is user content
            if !remaining.is_empty() {
                segments.push(Segment::User(remaining.to_string()));
            }
            break;
        }
    }

    segments
}

/// Render segments back to a string, replacing managed block content.
pub fn render_with_managed(segments: &[Segment], new_managed: &str) -> String {
    let mut out = String::new();
    let mut managed_replaced = false;

    for segment in segments {
        match segment {
            Segment::User(text) => out.push_str(text),
            Segment::Managed(_) => {
                if !managed_replaced {
                    out.push_str(BLOCK_BEGIN);
                    out.push('\n');
                    out.push_str(new_managed);
                    if !new_managed.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(BLOCK_END);
                    managed_replaced = true;
                }
                // Skip additional managed blocks (replace only first)
            }
        }
    }

    // If no managed block existed, append one
    if !managed_replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(BLOCK_BEGIN);
        out.push('\n');
        out.push_str(new_managed);
        if !new_managed.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(BLOCK_END);
        out.push('\n');
    }

    out
}

/// Sync a single managed doc file.
///
/// - If the file doesn't exist, creates it with managed blocks.
/// - If the file exists with managed blocks, replaces block content.
/// - If the file exists without managed blocks, appends blocks at end.
/// - User content outside managed blocks is NEVER modified.
pub fn sync_doc(file_path: &Path, managed_content: &str) -> Result<SyncResult> {
    let existed = file_path.exists();

    let current = if existed {
        std::fs::read_to_string(file_path).map_err(|e| KinError::io(file_path, e))?
    } else {
        String::new()
    };

    let segments = parse_segments(&current);
    let had_block = segments.iter().any(|s| matches!(s, Segment::Managed(_)));
    let new_content = render_with_managed(&segments, managed_content);

    // Only write if content changed
    if new_content != current {
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| KinError::io(parent, e))?;
        }
        std::fs::write(file_path, &new_content).map_err(|e| KinError::io(file_path, e))?;
    }

    Ok(SyncResult {
        path: file_path.to_path_buf(),
        created: !existed,
        had_managed_block: had_block,
        updated: new_content != current,
    })
}

/// Result of syncing a single doc file.
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub path: PathBuf,
    pub created: bool,
    pub had_managed_block: bool,
    pub updated: bool,
}

// ---------------------------------------------------------------------------
// Content generation from Kin state
// ---------------------------------------------------------------------------

/// Summary data extracted from the Kin graph for generating managed content.
#[derive(Debug, Clone, Default)]
pub struct RepoSummary {
    pub entity_count: usize,
    pub language_breakdown: HashMap<String, usize>,
    pub relation_count: usize,
    pub change_count: usize,
    pub work_item_count: usize,
    pub coverage_ratio: Option<f64>,
}

/// Generate the managed block content for a target file.
pub fn generate_managed_content(target: &ManagedDocTarget, summary: &RepoSummary) -> String {
    let mut out = String::new();
    out.push_str("<!-- Auto-generated by Kin. Do not edit this block manually. -->\n\n");

    for section in &target.sections {
        match section.as_str() {
            "summary" => {
                out.push_str("## Repository Summary\n\n");
                out.push_str(&format!("- **Entities**: {}\n", summary.entity_count));
                out.push_str(&format!("- **Relations**: {}\n", summary.relation_count));
                out.push_str(&format!("- **Changes**: {}\n", summary.change_count));
                if !summary.language_breakdown.is_empty() {
                    out.push_str("- **Languages**: ");
                    let mut langs: Vec<_> = summary.language_breakdown.iter().collect();
                    langs.sort_by(|a, b| b.1.cmp(a.1));
                    let parts: Vec<String> = langs
                        .iter()
                        .map(|(k, v)| format!("{} ({})", k, v))
                        .collect();
                    out.push_str(&parts.join(", "));
                    out.push('\n');
                }
                out.push('\n');
            }
            "conventions" => {
                out.push_str("## Conventions\n\n");
                out.push_str("- Use `kin commit -m \"message\"` for semantic commits\n");
                out.push_str("- Use `kin context <entity>` for token-budgeted context packs\n");
                out.push_str("- Use `kin review` for semantic impact analysis before merging\n");
                out.push_str("- Use `kin search <pattern>` to find entities across the codebase\n");
                out.push('\n');
            }
            "verification" => {
                out.push_str("## Verification\n\n");
                if let Some(ratio) = summary.coverage_ratio {
                    out.push_str(&format!(
                        "- **Test coverage ratio**: {:.0}%\n",
                        ratio * 100.0
                    ));
                }
                out.push_str(&format!("- **Work items**: {}\n", summary.work_item_count));
                out.push_str("- Use `kin verify <entity>` to check test coverage for an entity\n");
                out.push_str("- Use `kin work list` to see outstanding work items\n");
                out.push('\n');
            }
            "bootstrap" => {
                out.push_str(&render_bootstrap_section(&target.path));
            }
            "kin-first" => {
                out.push_str(&render_kin_first_section(&target.path));
            }
            _ => {
                // Unknown section — skip silently
            }
        }
    }

    out
}

fn render_bootstrap_section(target_path: &str) -> String {
    let file_name = Path::new(target_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("assistant");

    let mut out = String::new();
    out.push_str(&format!("## {} Bootstrap\n\n", file_name));
    out.push_str("This repository uses Kin semantic VCS.\n");
    out.push_str("Kin tracks entities (functions, classes, types) rather than lines.\n\n");

    match target_path {
        "CLAUDE.md" => {
            out.push_str("- Read `AGENTS.md` first, then this file.\n");
            out.push_str("- Configure native MCP with `claude mcp add kin -- kin mcp start`.\n");
            out.push_str("- Prefer `kin context`, `kin search`, `kin review`, and `kin verify` before broad file scans.\n");
            out.push_str("- Use Claude hooks for reminders like `kin review` before mutation and `kin commit` after validated changes.\n");
            out.push_str("- Keep the managed Kin block intact; add Claude-specific style notes outside the block.\n");
        }
        "CODEX.md" => {
            out.push_str("- Read `AGENTS.md` first, then this file.\n");
            out.push_str("- Configure native MCP with `codex mcp add kin -- kin mcp start`.\n");
            out.push_str("- Prefer `kin support`, `kin search`, `kin context`, and `kin review` before `rg` or `sed` loops.\n");
            out.push_str("- Treat this file as the Codex-specific companion to `AGENTS.md` for repo-local guidance.\n");
            out.push_str(
                "- Keep optional Codex-specific notes here; let Kin manage the bootstrap block.\n",
            );
        }
        "GEMINI.md" => {
            out.push_str("- Read `AGENTS.md` first, then this file.\n");
            out.push_str("- Configure native MCP with `gemini mcp add kin -- kin mcp start`.\n");
            out.push_str("- Prefer `kin context`, `kin search`, `kin review`, and `kin verify` for narrow context packs.\n");
            out.push_str("- Keep Gemini-specific prompting notes outside the managed block.\n");
        }
        "copilot-instructions.md" => {
            out.push_str("- Keep instructions short and tool-oriented.\n");
            out.push_str("- Prefer `kin search`, `kin context`, and `kin review` for precise semantic lookup.\n");
            out.push_str("- Avoid broad file dumps when Kin can provide targeted context.\n");
        }
        _ => {
            out.push_str("Key commands:\n");
            out.push_str("- `kin context <entity>` — get relevant context\n");
            out.push_str("- `kin commit -m \"msg\"` — semantic commit\n");
            out.push_str("- `kin review` — semantic review\n");
            out.push_str("- `kin search <pattern>` — find entities\n");
            out.push_str("- `kin support` — coverage report\n");
        }
    }

    out.push('\n');
    out
}

/// Render the "use Kin instead of X" comparison tables.
///
/// This is the shared content used by both `render_kin_first_section()` (managed-doc sync)
/// and `generate_assistant_prompt()` (prompt generation). Factored out to avoid duplication.
pub(crate) fn render_comparison_tables() -> String {
    let mut out = String::new();

    out.push_str("### Finding Code (use Kin instead of grep/rg/find)\n\n");
    out.push_str("| Instead of | Use | Why |\n");
    out.push_str("|------------|-----|-----|\n");
    out.push_str("| `grep -r function_name` | `kin search function_name` | Returns exact entity definitions with file:line, not noisy text matches |\n");
    out.push_str("| `rg 'class Foo'` | `kin search Foo --kind class` | Disambiguates: shows only definitions, not usages |\n");
    out.push_str("| `find . -name '*.rs'` then read each | `kin search --language rust` | Queries the semantic graph, no filesystem walk |\n");
    out.push('\n');

    out.push_str("### Reading Code (use Kin instead of cat/read entire files)\n\n");
    out.push_str("| Instead of | Use | Why |\n");
    out.push_str("|------------|-----|-----|\n");
    out.push_str("| Reading 5 files to find callers | `kin context <entity>` | Token-budgeted pack: focal entity + callers + dependencies |\n");
    out.push_str("| `cat src/foo.rs` (whole file) | `kin search foo` then read only the pointed-to file | 84% fewer tokens on average |\n");
    out.push_str("| Guessing which files matter | `kin support` | Coverage report showing all indexed entities, languages, relations |\n");
    out.push('\n');

    out.push_str("### Reviewing Changes (use Kin instead of git diff)\n\n");
    out.push_str("| Instead of | Use | Why |\n");
    out.push_str("|------------|-----|-----|\n");
    out.push_str(
        "| `git diff` | `kin review` | Entity-level diff + downstream impact + risk assessment |\n",
    );
    out.push_str("| Manual impact guessing | `kin review` impact section | Shows callers, dependents, contracts, tests affected |\n");
    out.push('\n');

    out.push_str("### Committing (use Kin for semantic history)\n\n");
    out.push_str("| Instead of | Use | Why |\n");
    out.push_str("|------------|-----|-----|\n");
    out.push_str("| `git commit` | `kin commit -m \"message\"` | Tracks entity-level changes, not line diffs |\n");
    out.push_str("| `git log` | `kin history` | Semantic change history per entity |\n");
    out.push('\n');

    out
}

/// Render the quick-reference CLI block.
pub(crate) fn render_quick_reference() -> String {
    let mut out = String::new();

    out.push_str("### Quick Reference\n\n");
    out.push_str("```bash\n");
    out.push_str("kin search <pattern>          # Find entities (functions, classes, types)\n");
    out.push_str(
        "kin search <p> --kind <k>     # Filter by kind: function, class, struct, trait\n",
    );
    out.push_str(
        "kin search <p> --language <l>  # Filter by language: rust, typescript, python, go, java\n",
    );
    out.push_str("kin context <entity>          # Token-budgeted context pack\n");
    out.push_str(
        "kin support                   # Coverage report (entities, languages, relations)\n",
    );
    out.push_str("kin review                    # Semantic diff + impact + risk assessment\n");
    out.push_str("kin commit -m \"msg\"           # Semantic commit\n");
    out.push_str("kin history                   # Entity change history\n");
    out.push_str("kin work list                 # Outstanding work items\n");
    out.push_str("kin verify <entity>           # Check test coverage for an entity\n");
    out.push_str("```\n\n");

    out
}

/// Render the MCP tool mapping table.
pub(crate) fn render_mcp_tool_mapping() -> String {
    let mut out = String::new();

    out.push_str("### MCP Tools (when connected via `kin mcp start`)\n\n");
    out.push_str("If you have MCP access, these tools map to the CLI commands above:\n\n");
    out.push_str("| MCP Tool | Equivalent CLI | Use For |\n");
    out.push_str("|----------|---------------|--------|\n");
    out.push_str("| `semantic_search` | `kin search` | Finding entities instead of grep |\n");
    out.push_str("| `get_context_pack` | `kin context` | Token-budgeted context instead of reading files |\n");
    out.push_str("| `impact_analysis` | `kin review` (impact section) | Understanding downstream effects |\n");
    out.push_str("| `semantic_review` | `kin review` | Full diff + impact + risk |\n");
    out.push_str("| `graph_neighborhood` | — | Exploring entity dependencies |\n");
    out.push_str("| `dead_code` | — | Finding unreachable code |\n");
    out.push('\n');

    out
}

fn render_kin_first_section(target_path: &str) -> String {
    let mut out = String::new();

    out.push_str("## Kin-First Workflow\n\n");
    out.push_str("This repository uses Kin semantic VCS. Kin indexes every function, class,\n");
    out.push_str("type, and trait into a graph with cross-file relations. **Use Kin tools\n");
    out.push_str("instead of raw file operations whenever possible.**\n\n");

    out.push_str(&render_comparison_tables());
    out.push_str(&render_quick_reference());

    // MCP tool mapping for MCP-capable assistants
    match target_path {
        "CLAUDE.md" | "CODEX.md" | "GEMINI.md" => {
            out.push_str(&render_mcp_tool_mapping());
        }
        _ => {}
    }

    out.push_str("### Key Principle\n\n");
    out.push_str("**Search semantically first, read files second.** Kin search returns 4-22x\n");
    out.push_str("less noise than grep and context packs use 84% fewer tokens than reading\n");
    out.push_str("all matching files. Only fall back to raw file reads when Kin doesn't have\n");
    out.push_str("what you need.\n");
    out.push('\n');

    out
}

/// Run a full sync for all enabled targets.
pub fn sync_all(
    layout: &KinLayout,
    config: &ManagedDocConfig,
    summary: &RepoSummary,
) -> Result<Vec<SyncResult>> {
    let working_dir = layout.working_dir();
    let mut results = Vec::new();

    for target in config.enabled_targets() {
        let file_path = working_dir.join(&target.path);
        let content = generate_managed_content(target, summary);
        let result = sync_doc(&file_path, &content)?;
        results.push(result);
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Segment parsing tests --

    #[test]
    fn parse_no_managed_blocks() {
        let content = "# My Doc\n\nUser content here.\n";
        let segments = parse_segments(content);
        assert_eq!(segments.len(), 1);
        assert!(matches!(&segments[0], Segment::User(s) if s == content));
    }

    #[test]
    fn parse_with_managed_block() {
        let content = format!(
            "# My Doc\n\n{}\nmanaged content\n{}\n\nFooter\n",
            BLOCK_BEGIN, BLOCK_END
        );
        let segments = parse_segments(&content);
        assert_eq!(segments.len(), 3);
        assert!(matches!(&segments[0], Segment::User(_)));
        assert!(matches!(&segments[1], Segment::Managed(s) if s.contains("managed content")));
        assert!(matches!(&segments[2], Segment::User(s) if s.contains("Footer")));
    }

    #[test]
    fn parse_empty_content() {
        let segments = parse_segments("");
        assert!(segments.is_empty());
    }

    #[test]
    fn parse_only_managed_block() {
        let content = format!("{}\nstuff\n{}", BLOCK_BEGIN, BLOCK_END);
        let segments = parse_segments(&content);
        assert_eq!(segments.len(), 1);
        assert!(matches!(&segments[0], Segment::Managed(_)));
    }

    // -- Render tests --

    #[test]
    fn render_replaces_managed_block() {
        let content = format!(
            "# Header\n\n{}\nold content\n{}\n\n# Footer\n",
            BLOCK_BEGIN, BLOCK_END
        );
        let segments = parse_segments(&content);
        let rendered = render_with_managed(&segments, "new content\n");

        assert!(rendered.contains("# Header"));
        assert!(rendered.contains("new content"));
        assert!(!rendered.contains("old content"));
        assert!(rendered.contains("# Footer"));
        assert!(rendered.contains(BLOCK_BEGIN));
        assert!(rendered.contains(BLOCK_END));
    }

    #[test]
    fn render_appends_block_when_missing() {
        let content = "# My Doc\n\nUser content.\n";
        let segments = parse_segments(content);
        let rendered = render_with_managed(&segments, "generated\n");

        assert!(rendered.starts_with("# My Doc"));
        assert!(rendered.contains("User content."));
        assert!(rendered.contains(BLOCK_BEGIN));
        assert!(rendered.contains("generated"));
        assert!(rendered.contains(BLOCK_END));
    }

    #[test]
    fn render_creates_from_empty() {
        let segments = parse_segments("");
        let rendered = render_with_managed(&segments, "fresh content\n");

        assert!(rendered.contains(BLOCK_BEGIN));
        assert!(rendered.contains("fresh content"));
        assert!(rendered.contains(BLOCK_END));
    }

    // -- User content preservation --

    #[test]
    fn user_content_preserved_on_sync() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("AGENTS.md");

        // Write initial file with user content and managed block
        let initial = format!(
            "# My Custom Header\n\nMy custom rules.\n\n{}\nold kin content\n{}\n\nMy footer.\n",
            BLOCK_BEGIN, BLOCK_END
        );
        std::fs::write(&file, &initial).unwrap();

        // Sync with new managed content
        let result = sync_doc(&file, "new kin content\n").unwrap();
        assert!(result.updated);
        assert!(!result.created);
        assert!(result.had_managed_block);

        // Verify user content is preserved
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("# My Custom Header"));
        assert!(content.contains("My custom rules."));
        assert!(content.contains("My footer."));
        assert!(content.contains("new kin content"));
        assert!(!content.contains("old kin content"));
    }

    #[test]
    fn sync_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("NEW_DOC.md");

        assert!(!file.exists());

        let result = sync_doc(&file, "generated content\n").unwrap();
        assert!(result.created);
        assert!(!result.had_managed_block);
        assert!(result.updated);

        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains(BLOCK_BEGIN));
        assert!(content.contains("generated content"));
        assert!(content.contains(BLOCK_END));
    }

    #[test]
    fn sync_appends_to_existing_without_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("AGENTS.md");

        std::fs::write(&file, "# Custom content\n\nDo not touch this.\n").unwrap();

        let result = sync_doc(&file, "kin data\n").unwrap();
        assert!(!result.created);
        assert!(!result.had_managed_block);
        assert!(result.updated);

        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("# Custom content"));
        assert!(content.contains("Do not touch this."));
        assert!(content.contains(BLOCK_BEGIN));
        assert!(content.contains("kin data"));
    }

    #[test]
    fn sync_no_write_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("DOC.md");

        let managed = "stable content\n";
        sync_doc(&file, managed).unwrap();
        let mtime1 = std::fs::metadata(&file).unwrap().modified().unwrap();

        // Small delay so mtime would differ if written
        std::thread::sleep(std::time::Duration::from_millis(50));

        let result = sync_doc(&file, managed).unwrap();
        assert!(!result.updated);

        let mtime2 = std::fs::metadata(&file).unwrap().modified().unwrap();
        assert_eq!(mtime1, mtime2);
    }

    #[test]
    fn disabled_target_not_synced() {
        let config = ManagedDocConfig {
            sync_mode: SyncMode::Manual,
            targets: vec![
                ManagedDocTarget {
                    path: "AGENTS.md".into(),
                    enabled: true,
                    sections: vec!["summary".into()],
                },
                ManagedDocTarget {
                    path: "DISABLED.md".into(),
                    enabled: false,
                    sections: vec!["summary".into()],
                },
            ],
        };

        let enabled = config.enabled_targets();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].path, "AGENTS.md");
    }

    // -- Config tests --

    #[test]
    fn config_default_has_agents_md() {
        let config = ManagedDocConfig::default();
        assert_eq!(config.sync_mode, SyncMode::Manual);
        assert!(config
            .targets
            .iter()
            .any(|t| t.path == "AGENTS.md" && t.enabled));
    }

    #[test]
    fn config_toml_roundtrip() {
        let config = ManagedDocConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ManagedDocConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.sync_mode, config.sync_mode);
        assert_eq!(parsed.targets.len(), config.targets.len());
    }

    #[test]
    fn config_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let config = ManagedDocConfig::default();
        config.save(&layout).unwrap();

        let loaded = ManagedDocConfig::load(&layout).unwrap();
        assert_eq!(loaded.sync_mode, SyncMode::Manual);
        assert_eq!(loaded.targets.len(), 5);
        assert!(loaded.targets.iter().any(|t| t.path == "CODEX.md"));
    }

    #[test]
    fn config_load_missing_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let config = ManagedDocConfig::load(&layout).unwrap();
        assert_eq!(config.sync_mode, SyncMode::Manual);
    }

    // -- Content generation tests --

    #[test]
    fn generate_summary_section() {
        let target = ManagedDocTarget {
            path: "AGENTS.md".into(),
            enabled: true,
            sections: vec!["summary".into()],
        };
        let mut langs = HashMap::new();
        langs.insert("TypeScript".into(), 50);
        langs.insert("Rust".into(), 30);
        let summary = RepoSummary {
            entity_count: 100,
            language_breakdown: langs,
            relation_count: 200,
            change_count: 10,
            ..Default::default()
        };

        let content = generate_managed_content(&target, &summary);
        assert!(content.contains("## Repository Summary"));
        assert!(content.contains("**Entities**: 100"));
        assert!(content.contains("**Relations**: 200"));
        assert!(content.contains("TypeScript"));
    }

    #[test]
    fn generate_bootstrap_section() {
        let target = ManagedDocTarget {
            path: "CLAUDE.md".into(),
            enabled: true,
            sections: vec!["bootstrap".into()],
        };
        let summary = RepoSummary::default();
        let content = generate_managed_content(&target, &summary);
        assert!(content.contains("CLAUDE Bootstrap"));
        assert!(content.contains("Kin semantic VCS"));
        assert!(content.contains("claude mcp add kin -- kin mcp start"));
    }

    #[test]
    fn generate_codex_bootstrap_section() {
        let target = ManagedDocTarget {
            path: "CODEX.md".into(),
            enabled: true,
            sections: vec!["bootstrap".into()],
        };
        let summary = RepoSummary::default();
        let content = generate_managed_content(&target, &summary);
        assert!(content.contains("CODEX Bootstrap"));
        assert!(content.contains("codex mcp add kin -- kin mcp start"));
    }

    #[test]
    fn generate_multiple_sections() {
        let target = ManagedDocTarget {
            path: "AGENTS.md".into(),
            enabled: true,
            sections: vec![
                "summary".into(),
                "conventions".into(),
                "verification".into(),
            ],
        };
        let summary = RepoSummary {
            entity_count: 50,
            coverage_ratio: Some(0.85),
            work_item_count: 3,
            ..Default::default()
        };

        let content = generate_managed_content(&target, &summary);
        assert!(content.contains("## Repository Summary"));
        assert!(content.contains("## Conventions"));
        assert!(content.contains("## Verification"));
        assert!(content.contains("85%"));
    }

    // -- Full sync integration --

    #[test]
    fn sync_all_creates_enabled_targets() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let config = ManagedDocConfig {
            sync_mode: SyncMode::Manual,
            targets: vec![
                ManagedDocTarget {
                    path: "AGENTS.md".into(),
                    enabled: true,
                    sections: vec!["summary".into()],
                },
                ManagedDocTarget {
                    path: "DISABLED.md".into(),
                    enabled: false,
                    sections: vec!["summary".into()],
                },
            ],
        };

        let summary = RepoSummary {
            entity_count: 42,
            ..Default::default()
        };

        let results = sync_all(&layout, &config, &summary).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].created);

        // AGENTS.md should exist
        assert!(dir.path().join("AGENTS.md").exists());
        // DISABLED.md should NOT exist
        assert!(!dir.path().join("DISABLED.md").exists());

        let content = std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(content.contains("42"));
    }

    #[test]
    fn deterministic_rendering() {
        let target = ManagedDocTarget {
            path: "TEST.md".into(),
            enabled: true,
            sections: vec!["summary".into(), "conventions".into()],
        };
        let summary = RepoSummary {
            entity_count: 10,
            relation_count: 5,
            ..Default::default()
        };

        let content1 = generate_managed_content(&target, &summary);
        let content2 = generate_managed_content(&target, &summary);
        assert_eq!(content1, content2);
    }
}
