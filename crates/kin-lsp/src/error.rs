// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

pub type Result<T> = std::result::Result<T, LspError>;

#[derive(Debug, Error)]
pub enum LspError {
    #[error("server not found: {0}")]
    ServerNotFound(String),

    #[error("server failed to start: {0}")]
    ServerStartFailed(String),

    #[error("server initialization failed: {0}")]
    InitializeFailed(String),

    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("timeout waiting for response")]
    Timeout,

    #[error("server shutdown unexpectedly")]
    ServerDied,

    /// A start or handshake failure, carrying whatever the server wrote to its
    /// own stderr before it went.
    ///
    /// The reason is the original failure's message; the tail is bounded and
    /// may be truncated to its last bytes. This variant exists because a server
    /// that dies before it can frame a JSON-RPC reply has nowhere else to say
    /// why, and discarding stderr made those failures unattributable.
    #[error("{reason} (server stderr: {stderr})")]
    ServerFailedWithStderr { reason: String, stderr: String },

    /// The server answered that the request does not apply where it was asked,
    /// in one of the exact method and message pairs [`declined_answer`] knows.
    #[error("{method} declined: {message}")]
    Declined { method: String, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// How a request that did not produce an answer ended, in the order every
/// enrichment pass decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryErrorClass {
    /// The server can no longer answer anything: stop asking it.
    SessionEnded,
    /// No answer arrived in time. Skip this question; several in a row mean
    /// the server has stopped answering.
    TimedOut,
    /// The server answered that the request does not apply at this position.
    /// An answer with nothing in it: skip the position and hold nothing back.
    Declined,
    /// Anything else. The question got no considered answer, so whatever
    /// asked it did not finish, and the file it belongs to is not complete.
    Failed,
}

impl LspError {
    /// Whether the server can no longer answer anything, as opposed to one
    /// request it could not answer or one answer that could not be proven.
    pub fn ends_the_session(&self) -> bool {
        matches!(
            self,
            LspError::ServerDied
                | LspError::Io(_)
                | LspError::ServerNotFound(_)
                | LspError::ServerStartFailed(_)
                | LspError::InitializeFailed(_)
                | LspError::ServerFailedWithStderr { .. }
        )
    }

    /// Whether the server declined this request as not applying where it was
    /// asked. Only [`JsonRpcClient::request`](crate::client::JsonRpcClient)
    /// makes one, from the pairs [`declined_answer`] knows.
    pub fn is_declined(&self) -> bool {
        matches!(self, LspError::Declined { .. })
    }

    /// Whether this failure refuses the question for good: the server
    /// answered, and the answer is one this build cannot prove or decode, so
    /// asking the same server about the same bytes returns it again.
    ///
    /// A prepared call hierarchy item that is not the queried entity, a range
    /// that names no position in the admitted text, a declaration whose name
    /// its own line does not spell, a site in a file the graph does not
    /// admit, and an answer whose shape does not decode are all refusals. The
    /// entity they are about is unprovable by this server, which settles it:
    /// retrying costs a query and learns nothing.
    ///
    /// The one error a server returns itself that is a refusal is a
    /// TypeScript compiler's internal assertion (see
    /// [`typescript_internal_assertion`]): the compiler asserts on the same
    /// bytes the same way every time.
    ///
    /// Not a refusal: a timeout, a server that stopped answering, and any
    /// other error the server returned itself, which may be load, a restart
    /// or a request it cancelled. Those may answer if asked again, so their
    /// work stays owed. A decline is its own class and never reaches here.
    pub fn is_refusal(&self) -> bool {
        match self {
            LspError::Protocol(_) | LspError::Json(_) => true,
            LspError::JsonRpc(error) => typescript_internal_assertion(error),
            _ => false,
        }
    }

    /// The one classification every pass applies, in its one order:
    /// session-ending, then timeout, then decline, then failure.
    pub fn class(&self) -> QueryErrorClass {
        if self.ends_the_session() {
            QueryErrorClass::SessionEnded
        } else if matches!(self, LspError::Timeout) {
            QueryErrorClass::TimedOut
        } else if self.is_declined() {
            QueryErrorClass::Declined
        } else {
            QueryErrorClass::Failed
        }
    }
}

/// Whether a JSON-RPC error is TypeScript's compiler failing one of its own
/// assertions: typescript-language-server relays it as `TypeScript Server
/// Error (<version>)` with a `Debug Failure.` line, from `Debug.fail` and
/// `Debug.assert` inside the compiler.
///
/// Such an assertion is a property of the program and the position, not of
/// load: on drizzle-orm TypeScript 5.6.3 failed 514 definition queries in
/// `getTextOfPropertyName`, the same ones in every sweep, and holding their
/// 230 files owed asked them again for nothing.
pub fn typescript_internal_assertion(error: &str) -> bool {
    let Ok(error) = serde_json::from_str::<serde_json::Value>(error) else {
        return false;
    };
    let Some(message) = error.get("message").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let mut lines = message.lines();
    lines
        .next()
        .is_some_and(|first| first.contains("TypeScript Server Error"))
        && lines.any(|line| line.trim_start().starts_with("Debug Failure."))
}

/// How a known declining message is matched.
enum Wording {
    Exact(&'static str),
    Prefix(&'static str),
    Suffix(&'static str),
}

/// The answers a server gives when a request does not apply where it was
/// asked, as exact method and message pairs, never a bare error code.
///
/// Each was observed from gopls v0.22.0 on the GitHub CLI and is a property of
/// the source at that position, so asking again returns it again. gopls sends
/// every handler error with code 0, including "no package metadata for file"
/// for a package it could not load, so the code alone says nothing: a pair
/// that is not listed here is a failure, and the file it belongs to is retried.
const DECLINED_ANSWERS: &[(&str, Wording)] = &[
    // A keyword, a package clause or a declaration's own line.
    (
        "textDocument/typeDefinition",
        Wording::Exact("no enclosing expression has a type"),
    ),
    // A package name, a builtin, or a value of an unnamed type.
    (
        "textDocument/typeDefinition",
        Wording::Prefix("cannot find type name(s) from type "),
    ),
    // A method, field or value asked for its type hierarchy.
    (
        "textDocument/prepareTypeHierarchy",
        Wording::Exact("not a type name"),
    ),
    // A type, field, constant or variable asked for its call hierarchy.
    (
        "textDocument/prepareCallHierarchy",
        Wording::Suffix(" is not a function"),
    ),
    // A package clause asked for its call hierarchy.
    (
        "textDocument/prepareCallHierarchy",
        Wording::Exact("no symbol here"),
    ),
    (
        "textDocument/prepareCallHierarchy",
        Wording::Exact("identifier not found"),
    ),
    // A position on a keyword asked for its references.
    (
        "textDocument/references",
        Wording::Exact("no identifier found"),
    ),
];

/// The declining message, when this JSON-RPC error answering `method` is one
/// of [`DECLINED_ANSWERS`].
///
/// `error` is the JSON-RPC error object as the client received it. Code 0 is
/// required as well as the wording, because that is how gopls sends them.
pub fn declined_answer(method: &str, error: &str) -> Option<String> {
    let error: serde_json::Value = serde_json::from_str(error).ok()?;
    if error.get("code").and_then(serde_json::Value::as_i64) != Some(0) {
        return None;
    }
    let message = error.get("message").and_then(serde_json::Value::as_str)?;
    DECLINED_ANSWERS
        .iter()
        .filter(|(declining, _)| *declining == method)
        .any(|(_, wording)| match wording {
            Wording::Exact(text) => message == *text,
            Wording::Prefix(text) => message.starts_with(text),
            Wording::Suffix(text) => message.ends_with(text) && message.len() > text.len(),
        })
        .then(|| message.to_string())
}

#[cfg(test)]
mod tests {
    use super::{declined_answer, LspError, QueryErrorClass};

    fn rpc(code: i64, message: &str) -> String {
        serde_json::json!({"code": code, "message": message}).to_string()
    }

    /// Only the observed method and message pairs decline, and only with the
    /// code gopls sends them with.
    #[test]
    fn only_a_known_answer_to_its_own_method_is_a_decline() {
        let declined = |method: &str, message: &str| declined_answer(method, &rpc(0, message));
        assert!(declined(
            "textDocument/typeDefinition",
            "no enclosing expression has a type"
        )
        .is_some());
        assert!(declined(
            "textDocument/typeDefinition",
            "cannot find type name(s) from type invalid type"
        )
        .is_some());
        assert!(declined("textDocument/prepareTypeHierarchy", "not a type name").is_some());
        assert!(declined(
            "textDocument/prepareCallHierarchy",
            "Issue is not a function"
        )
        .is_some());
        assert!(declined("textDocument/prepareCallHierarchy", "no symbol here").is_some());
        assert!(declined("textDocument/references", "no identifier found").is_some());

        // The wording belongs to its method.
        assert!(declined("textDocument/definition", "no identifier found").is_none());
        assert!(declined("callHierarchy/outgoingCalls", "no symbol here").is_none());
        assert!(declined("typeHierarchy/supertypes", "not a type name").is_none());
        assert!(declined("textDocument/prepareCallHierarchy", " is not a function").is_none());
        // gopls cannot load the file's package: a failure, not a decline.
        assert!(declined(
            "textDocument/typeDefinition",
            "no package metadata for file file:///w/main.go"
        )
        .is_none());
        assert!(declined("textDocument/references", "no package metadata for file").is_none());
        // The wording with any other code is not gopls declining.
        assert!(declined_answer(
            "textDocument/prepareTypeHierarchy",
            &rpc(-32603, "not a type name")
        )
        .is_none());
        assert!(declined_answer(
            "textDocument/references",
            &rpc(-32803, "no identifier found")
        )
        .is_none());
        assert!(declined_answer("textDocument/references", "not json").is_none());
    }

    /// Only an answer this build cannot prove or decode refuses a question
    /// for good; everything that may answer if asked again does not.
    #[test]
    fn only_an_unprovable_answer_is_a_refusal() {
        assert!(LspError::Protocol(
            "prepared call hierarchy source is not the queried entity".into()
        )
        .is_refusal());
        let undecodable = serde_json::from_str::<Vec<u32>>("{}").unwrap_err();
        assert!(LspError::Json(undecodable).is_refusal());
        for unanswered in [
            LspError::Timeout,
            LspError::ServerDied,
            LspError::JsonRpc(rpc(-32801, "content modified")),
            LspError::Io(std::io::Error::other("broken pipe")),
            LspError::Declined {
                method: "textDocument/references".into(),
                message: "no identifier found".into(),
            },
        ] {
            assert!(!unanswered.is_refusal(), "{unanswered}");
        }
    }

    /// TypeScript answers a question its own compiler asserts on with the
    /// assertion, and asks of the same bytes assert the same way every time:
    /// on drizzle-orm TypeScript 5.6.3 failed 514 definition queries in
    /// `getTextOfPropertyName`, identically in every sweep. That is a
    /// refusal. Any other error tsserver returns, and one that only mentions
    /// the words, is not.
    #[test]
    fn a_typescript_internal_assertion_is_a_refusal() {
        let assertion = rpc(
            1,
            "<main> TypeScript Server Error (5.6.3)\nDebug Failure.\nError: Debug Failure.\n    \
             at getTextOfPropertyName (/repo/node_modules/typescript/lib/typescript.js:17277:16)",
        );
        assert!(LspError::JsonRpc(assertion).is_refusal());
        let false_expression = rpc(
            1,
            "<semantic> TypeScript Server Error (5.9.3)\nDebug Failure. False expression: \
             Expected node to be a declaration\nError: Debug Failure. False expression",
        );
        assert!(LspError::JsonRpc(false_expression).is_refusal());
        for other in [
            rpc(1, "<main> TypeScript Server Error (5.6.3)\nNo Project."),
            rpc(
                1,
                "<main> TypeScript Server Error (5.6.3)\nCould not find source file",
            ),
            rpc(0, "Debug Failure."),
            rpc(-32603, "the request mentions a Debug Failure. somewhere"),
            "not json".to_string(),
        ] {
            assert!(!LspError::JsonRpc(other.clone()).is_refusal(), "{other}");
        }
    }

    /// The one order: session-ending, then timeout, then decline, then failure.
    #[test]
    fn every_error_has_one_class() {
        let declined = LspError::Declined {
            method: "textDocument/references".into(),
            message: "no identifier found".into(),
        };
        assert_eq!(declined.class(), QueryErrorClass::Declined);
        assert_eq!(LspError::Timeout.class(), QueryErrorClass::TimedOut);
        assert_eq!(LspError::ServerDied.class(), QueryErrorClass::SessionEnded);
        assert_eq!(
            LspError::JsonRpc(rpc(0, "no package metadata for file")).class(),
            QueryErrorClass::Failed
        );
        assert_eq!(
            LspError::Protocol("ambiguous".into()).class(),
            QueryErrorClass::Failed
        );
    }
}
