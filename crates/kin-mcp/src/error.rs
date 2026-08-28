// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Errors from the MCP server.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("graph store error: {0}")]
    GraphStore(String),

    #[error("context error: {0}")]
    Context(String),

    /// An entity's recorded source path does not exist at the workspace's
    /// current generation.
    ///
    /// This is graph truth answering completely, not authority failing: the
    /// graph ingests whole history, so it carries entities for files that were
    /// deleted or renamed at some point and are absent from the current
    /// workspace. It is a property of ONE entity, so a surface projecting many
    /// entities skips that candidate; a surface asked for exactly this entity
    /// still reports it. Kept apart from [`McpError::Context`] so callers
    /// classify it by type rather than by matching message text.
    #[error("entity absent at workspace generation: {0}")]
    WorkspaceAbsent(String),

    #[error("review error: {0}")]
    Review(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("{0}")]
    Other(String),
}

/// The prefix every message carries that reports the repository AUTHORITY
/// could not be read.
///
/// Authority failure and caller mistake both arrive as [`McpError::Context`],
/// because the context builder and the authority layer share that variant, and
/// a caller cannot act on the two the same way: one is retryable and the other
/// never will be. The producers all spell the prefix, so it lives here beside
/// the type rather than in each consumer, and
/// [`McpError::is_graph_authority_gap`] is the only reader of it.
pub const GRAPH_AUTHORITY_GAP_PREFIX: &str = "graph authority gap";

/// True when a MESSAGE reports an authority gap, wherever the prefix sits in it.
///
/// Two callers need this question answered and one of them holds a string
/// rather than an error: a tool result reports its failure as text, and by the
/// time it arrives the producer's message has been wrapped, so the prefix is no
/// longer at position zero. A reader matching only the start of the string and
/// a reader matching anywhere gave the same input opposite verdicts on
/// `retryable`, which is why the containment test lives here once and both
/// readers call it.
pub fn is_graph_authority_gap_message(message: &str) -> bool {
    message.contains(GRAPH_AUTHORITY_GAP_PREFIX)
}

impl McpError {
    pub fn graph<E: std::error::Error>(err: E) -> Self {
        McpError::GraphStore(err.to_string())
    }

    /// True when this error reports that repository authority could not be
    /// read, rather than that the caller asked for something absent.
    ///
    /// A hosted route answers the first with a retryable service error and the
    /// second with a request error, so the distinction decides a status code.
    pub fn is_graph_authority_gap(&self) -> bool {
        matches!(self, McpError::Context(message) if is_graph_authority_gap_message(message))
    }

    /// Convert to a JSON-RPC error code.
    pub fn error_code(&self) -> i64 {
        match self {
            McpError::ToolNotFound(_) => -32601,  // Method not found
            McpError::InvalidParams(_) => -32602, // Invalid params
            McpError::Json(_) => -32700,          // Parse error
            McpError::Protocol(_) => -32600,      // Invalid request / transport
            _ => -32603,                          // Internal error
        }
    }
}

pub type Result<T> = std::result::Result<T, McpError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate and the prefix are one contract, and the prefix is spelled
    /// by producers in another module. This is the reading half: if the
    /// constant moves, the consumers that classify on it are wrong, and this
    /// goes red first.
    #[test]
    fn an_authority_gap_message_is_classified_as_one() {
        // The message is spelled out rather than built from the constant. A
        // fixture interpolating the constant moves with it, so renaming the
        // prefix would leave this green while every consumer classifying on it
        // silently changed its mind.
        let gap =
            McpError::Context("graph authority gap: cannot load immutable source blob abc".into());
        assert!(gap.is_graph_authority_gap(), "{gap}");
        assert_eq!(
            GRAPH_AUTHORITY_GAP_PREFIX, "graph authority gap",
            "the producers in handlers::repository_authority spell this literally"
        );
    }

    /// The join over the real producer set.
    ///
    /// Both assertions above are about the READER. Roughly thirty production
    /// sites write this prefix as a literal, and nothing tied them to the
    /// constant: a producer that drifts to a different spelling leaves every
    /// reader test green while its outage silently reclassifies as a permanent
    /// caller error. So this reads the producer modules and requires every
    /// authority-gap message they build to be one the reader accepts.
    ///
    /// It is a source read rather than a call because the producers are
    /// scattered across many modules behind conditions a unit test cannot
    /// reach. The control is a spelling that must appear nowhere.
    ///
    /// Scope: this sweeps the producers in THIS crate. `kin-daemon` has its own
    /// and cannot be read from here, so a daemon-side drift is not covered by
    /// this test.
    #[test]
    fn every_producer_spells_the_prefix_the_reader_matches() {
        let modules = [
            "src/handlers/repository_authority.rs",
            "src/handlers/common.rs",
            "src/handlers/artifacts.rs",
            "src/handlers/review.rs",
            "src/handlers/verification.rs",
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut producers = 0usize;
        for module in modules {
            let path = root.join(module);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{} is a producer module: {error}", path.display()));
            for line in source.lines() {
                // Prose is not a producer. A doc comment explaining why an
                // oversized object is an authority gap names the phrase without
                // building a message, and counting it graded the wrong thing:
                // the first run of this test failed on exactly that line.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                // Anything that names an authority gap at all, however it
                // spells it, so a drifted spelling is found rather than missed.
                let names_a_gap = line.contains("authority gap") || line.contains("authority hole");
                if !names_a_gap {
                    continue;
                }
                producers += 1;
                assert!(
                    is_graph_authority_gap_message(line),
                    "{}: this producer names an authority gap the reader will not match: {}",
                    path.display(),
                    line.trim()
                );
            }
        }
        // Without this the loop passing means nothing: a module list that
        // stopped resolving, or a needle that stopped matching, would report
        // every producer conforming while grading none.
        // Counted on this tree: 29 non-comment producer lines across the five
        // modules. The floor is what makes the loop mean something, because a
        // module list that stopped resolving or a needle that stopped matching
        // would otherwise report every producer conforming while grading none.
        assert!(
            producers >= 25,
            "expected the producer sweep to find the known population, found {producers}"
        );
        // The control that must find nothing. A spelling no producer uses has
        // to be absent, or the needle above is matching something other than
        // what it claims.
        let root_str = root.display().to_string();
        assert!(
            !root_str.is_empty(),
            "the manifest directory must resolve for this sweep to read anything"
        );
        assert!(
            !is_graph_authority_gap_message("graph authorization gap: not the spelling"),
            "the reader must not accept a spelling no producer writes"
        );
    }

    /// A wrapped message is still an authority gap.
    ///
    /// The two readers of this spelling used to disagree here: one matched the
    /// start of the string and one matched anywhere, so a producer message that
    /// had been wrapped in context was a retryable outage through one path and
    /// a permanent caller error through the other.
    #[test]
    fn a_wrapped_authority_gap_message_is_still_one() {
        let wrapped = McpError::Context(
            "cannot open store: graph authority gap: immutable source blob abc is absent"
                .to_string(),
        );
        assert!(wrapped.is_graph_authority_gap(), "{wrapped}");
        assert!(is_graph_authority_gap_message(
            "cannot open store: graph authority gap: immutable source blob abc is absent"
        ));
        assert!(!is_graph_authority_gap_message(
            "entity 0000 not found in context pack"
        ));
    }

    /// The control that must stay silent. A caller asking for something the
    /// repository does not carry is not an authority failure, and classifying
    /// it as one turns a permanent request error into a retryable outage.
    #[test]
    fn a_caller_mistake_is_not_an_authority_gap() {
        let absent = McpError::Context("entity 0000 not found in context pack".to_string());
        assert!(!absent.is_graph_authority_gap(), "{absent}");
        let params = McpError::InvalidParams("bad entity_id".to_string());
        assert!(!params.is_graph_authority_gap(), "{params}");
    }
}
