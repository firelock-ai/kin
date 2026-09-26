// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconcile TypeScript's binding selection with its initializer call range.
//!
//! The server prepares `const f = () => g()` with `f` as selectionRange and
//! `() => g()` as range. Those are disjoint, unlike an ordinary function's
//! ranges. Only the exact name and initializer of one parsed declarator prove
//! this shape. This is an enrichment boundary over already admitted bytes,
//! never a filesystem lookup or a name-based substitute for entity identity.

use crate::{enrichment::EntityRef, protocol::Position};
use kin_model::{EntityKind, SourceSpan};
use tree_sitter_language::LanguageFn;

/// The TypeScript and TSX grammars the binding-initializer proof parses with.
///
/// This crate links no TypeScript grammar of its own. Whoever starts a server
/// passes one to [`crate::lifecycle::LspServer::start`], so the grammar a proof
/// rests on is chosen where the server is started. Kin passes its patched
/// grammar; a caller may pass the upstream `tree-sitter-typescript` grammars.
#[derive(Clone, Copy)]
pub struct TypeScriptGrammars {
    pub typescript: LanguageFn,
    pub tsx: LanguageFn,
}

impl std::fmt::Debug for TypeScriptGrammars {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TypeScriptGrammars { .. }")
    }
}

/// `false` without grammars: a server started without them proves no binding
/// initializer, and never proves one wrongly.
pub(crate) fn proves_binding_initializer(
    grammars: Option<&TypeScriptGrammars>,
    caller: &EntityRef,
    text: &str,
    request: &Position,
    selection: &SourceSpan,
    enclosing: &SourceSpan,
) -> bool {
    if caller.kind != EntityKind::Function
        || !caller.declares_name
        || selection.start_line != request.line
        || selection.end_line != selection.start_line
        || selection.file.0 != caller.file_path
        || enclosing.file.0 != caller.file_path
    {
        return false;
    }
    // The request uses UTF-16; the captured and parsed spans use UTF-8 bytes.
    let positions = crate::source_positions::SourcePositions::new(&caller.file_path, text);
    if positions.byte_column(request).ok() != Some(selection.start_col) {
        return false;
    }
    let grammar = match std::path::Path::new(&caller.file_path)
        .extension()
        .and_then(|ext| ext.to_str())
    {
        Some("ts") => grammars.map(|g| g.typescript),
        Some("tsx") => grammars.map(|g| g.tsx),
        _ => return false,
    };
    let Some(grammar) = grammar else {
        return false;
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&grammar.into()).is_err() {
        return false;
    }
    let Some(tree) = parser.parse(text, None) else {
        return false;
    };
    let Some(name) = tree
        .root_node()
        .descendant_for_byte_range(selection.start_byte, selection.end_byte)
    else {
        return false;
    };
    if name.kind() != "identifier"
        || name.start_byte() != selection.start_byte
        || name.end_byte() != selection.end_byte
        || name.utf8_text(text.as_bytes()).ok() != Some(caller.name.as_str())
    {
        return false;
    }
    let Some(declarator) = name.parent() else {
        return false;
    };
    if declarator.kind() != "variable_declarator"
        || declarator.has_error()
        || declarator.child_by_field_name("name") != Some(name)
        || declarator.start_position().row != caller.start_line as usize
        || declarator.start_position().column != caller.start_col as usize
        || declarator.end_position().row != caller.end_line as usize
    {
        return false;
    }
    let Some(initializer) = declarator.child_by_field_name("value") else {
        return false;
    };
    matches!(
        initializer.kind(),
        "arrow_function" | "function_expression" | "function" | "generator_function"
    ) && initializer.start_byte() == enclosing.start_byte
        && initializer.end_byte() == enclosing.end_byte
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::{enrich_entity_calls, EntityIndex};
    use crate::lifecycle::LspServer;
    use crate::protocol;
    use kin_model::{EntityId, FilePathId, GraphNodeId};
    use kin_parser::{LanguageAdapter, TypeScriptAdapter};
    use serde_json::{json, Value};

    const PEER: &str = include_str!("enrichment_test_peer.py");

    /// The grammars the daemon starts every language server with.
    fn kin_grammars() -> TypeScriptGrammars {
        TypeScriptGrammars {
            typescript: kin_grammar_typescript::LANGUAGE_TYPESCRIPT,
            tsx: kin_grammar_typescript::LANGUAGE_TSX,
        }
    }
    const PREPARE: &str = "textDocument/prepareCallHierarchy";
    const OUTGOING: &str = "callHierarchy/outgoingCalls";

    struct Fixture {
        root: std::path::PathBuf,
        text: String,
        caller: EntityRef,
        target: EntityRef,
        index: EntityIndex,
        responses: Value,
    }

    fn range(text: &str, needle: &str) -> Value {
        let start = text.find(needle).unwrap();
        let position = |byte| {
            let prefix = &text[..byte];
            json!({"line": prefix.bytes().filter(|b| *b == b'\n').count(),
                "character": prefix.rsplit('\n').next().unwrap().encode_utf16().count()})
        };
        json!({"start":position(start), "end":position(start + needle.len())})
    }

    impl Fixture {
        fn new(text: &str, name: &str, initializer: &str) -> Self {
            Self::in_file(text, name, initializer, "sample.ts")
        }

        fn in_file(text: &str, name: &str, initializer: &str, file: &str) -> Self {
            let root = std::env::temp_dir().join(format!("kin-ts-call-ranges-{}", EntityId::new()));
            std::fs::create_dir(&root).unwrap();
            let tree = TypeScriptAdapter.parse(text.as_bytes()).unwrap();
            let parsed = TypeScriptAdapter
                .extract(&tree, text.as_bytes(), &FilePathId::new(file))
                .unwrap();
            // Use the product parser's actual declarator ownership and spans.
            // Handwritten ranges would miss a disagreement with graph ingestion.
            let refs: Vec<_> = parsed
                .entities
                .iter()
                .map(|entity| EntityRef {
                    id: EntityId::new(),
                    name: entity.name.clone(),
                    file_path: file.into(),
                    start_line: entity.span.start_line,
                    start_col: entity.span.start_col,
                    end_line: entity.span.end_line,
                    name_line: entity.span.start_line,
                    name_col: entity.span.start_col,
                    declares_name: EntityRef::kind_declares_name(entity.kind),
                    kind: entity.kind,
                })
                .collect();
            let caller = refs
                .iter()
                .find(|entity| entity.name == name)
                .unwrap()
                .clone();
            let target = refs
                .iter()
                .find(|entity| entity.name == "target")
                .unwrap()
                .clone();
            let index = EntityIndex::new(refs, &root);
            let uri = protocol::path_to_uri(&root.join(file));
            let selection = range(text, name);
            let item = json!({"name":name,"kind":12,"detail":null,"uri":uri,"selectionRange":selection,
                "range":range(text, initializer)});
            let target_item = json!({"name":"target","kind":12,"uri":uri,
                "range":range(text, "function target() { return 1; }"),
                "selectionRange":range(text,"target")});
            let offset = text.find(initializer).unwrap() + initializer.find("target").unwrap();
            let positions = crate::source_positions::SourcePositions::new(file, text);
            let prefix = &text[..offset];
            let line = prefix.bytes().filter(|b| *b == b'\n').count() as u32;
            let col = prefix.rsplit('\n').next().unwrap().len() as u32;
            let call = json!({"start":positions.byte_position(line,col).unwrap(),
                "end":positions.byte_position(line,col+6).unwrap()});
            let responses = json!({PREPARE:{"result":[item]},
                OUTGOING:{"result":[{"to":target_item,"fromRanges":[call]}]}});
            Self {
                root,
                text: text.into(),
                caller,
                target,
                index,
                responses,
            }
        }

        async fn check(&self, accepted: bool) {
            self.check_with(Some(kin_grammars()), accepted).await;
        }

        async fn check_with(&self, grammars: Option<TypeScriptGrammars>, accepted: bool) {
            let server = LspServer::scripted_for_tests(PEER, self.responses.clone());
            let server = match grammars {
                Some(grammars) => server.with_typescript_grammars(grammars),
                None => server,
            };
            let answer = enrich_entity_calls(
                &server,
                &self.caller,
                &self.index,
                &self.root,
                Some(&|file| (file == self.caller.file_path).then(|| self.text.clone())),
            )
            .await;
            let seen: Vec<Value> = serde_json::from_value(
                server
                    .client
                    .request("test/seen", Value::Null)
                    .await
                    .unwrap(),
            )
            .unwrap();
            if accepted {
                let relations = answer
                    .expect("source-backed initializer is accepted")
                    .relations;
                assert!(
                    relations
                        .iter()
                        .any(|r| r.src == GraphNodeId::Entity(self.caller.id)
                            && r.dst == GraphNodeId::Entity(self.target.id)),
                    "{relations:?}"
                );
                let span = relations[0].evidence[0].source_span.as_ref().unwrap();
                assert_eq!(&self.text[span.start_byte..span.end_byte], "target");
                // Reconciliation validates the original item; it never widens
                // the server's range or substitutes a different binding.
                assert_eq!(
                    seen.iter().find(|r| r["method"] == OUTGOING).unwrap()["params"]["item"],
                    self.responses[PREPARE]["result"][0]
                );
            } else {
                assert!(answer.is_err(), "unproven item accepted: {answer:?}");
                assert!(!seen.iter().any(|r| r["method"] == OUTGOING));
            }
            server.shutdown().await.unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[tokio::test]
    async fn parsed_binding_initializers_keep_exact_call_evidence() {
        for initializer in [
            "() => target()",
            "function () { return target(); }",
            "async () => target()",
            "function* () { yield target(); }",
        ] {
            let text =
                format!("function target() {{ return 1; }}\nexport const arrow = {initializer};\n");
            Fixture::new(&text, "arrow", initializer).check(true).await;
        }
        Fixture::new("function target() { return 1; }\nexport const arrow: () => number =\n  () => target();\n",
            "arrow","() => target()").check(true).await;
        Fixture::new(
            "function target() { return 1; }\n/* 😀 */ const arrow = () => target();\n",
            "arrow",
            "() => target()",
        )
        .check(true)
        .await;
    }

    #[tokio::test]
    async fn reconciliation_is_confined_to_typescript_and_tsx() {
        let text = "function target() { return 1; }\nconst arrow = () => target();\n";
        Fixture::in_file(text, "arrow", "() => target()", "sample.tsx")
            .check(true)
            .await;
        Fixture::in_file(text, "arrow", "() => target()", "sample.js")
            .check(false)
            .await;
    }

    #[tokio::test]
    async fn another_declarators_call_site_is_refused_after_valid_preparation() {
        let text = "function target() { return 1; }\nconst arrow = () => target(), other = () => target() + 1;\n";
        let mut f = Fixture::new(text, "arrow", "() => target()");
        let start = text.rfind("target()").unwrap();
        let col = text[..start].rsplit('\n').next().unwrap().len();
        f.responses[OUTGOING]["result"][0]["fromRanges"] = json!([{
            "start":{"line":1,"character":col},"end":{"line":1,"character":col+6}
        }]);
        let server = LspServer::scripted_for_tests(PEER, f.responses.clone())
            .with_typescript_grammars(kin_grammars());
        let answer = enrich_entity_calls(
            &server,
            &f.caller,
            &f.index,
            &f.root,
            Some(&|_| Some(text.into())),
        )
        .await;
        assert!(matches!(answer,Err(crate::LspError::Protocol(reason))
            if reason.contains("outside the proven binding initializer")));
        let seen: Vec<Value> = serde_json::from_value(
            server
                .client
                .request("test/seen", Value::Null)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(seen.iter().any(|request| request["method"] == OUTGOING));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_site_cap_cannot_hide_a_foreign_initializer_call() {
        let initializer = format!("() => {{\n{}}}", "target();\n".repeat(64));
        let text = format!("function target() {{ return 1; }}\nconst arrow = {initializer}; const other = () => target();\n");
        let mut f = Fixture::new(&text, "arrow", &initializer);
        let calls: Vec<Value> = text
            .match_indices("target()")
            .skip(1)
            .map(|(offset, _)| {
                let prefix = &text[..offset];
                let line = prefix.bytes().filter(|b| *b == b'\n').count();
                let col = prefix.rsplit('\n').next().unwrap().len();
                json!({"start":{"line":line,"character":col},"end":{"line":line,"character":col+6}})
            })
            .collect();
        assert_eq!(calls.len(), 65);
        f.responses[OUTGOING]["result"][0]["fromRanges"] = json!(calls);
        let server = LspServer::scripted_for_tests(PEER, f.responses.clone())
            .with_typescript_grammars(kin_grammars());
        let answer = enrich_entity_calls(
            &server,
            &f.caller,
            &f.index,
            &f.root,
            Some(&|_| Some(text.clone())),
        )
        .await;
        assert!(matches!(answer,Err(crate::LspError::Protocol(reason))
            if reason.contains("outside the proven binding initializer")));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn another_declarators_body_is_never_the_queried_binding() {
        for text in [
            "function target() { return 1; }\nconst arrow = () => target();\nconst other = () => target() + 1;\n",
            "function target() { return 1; }\nconst arrow = () => target(), other = () => target() + 1;\n",
        ] {
            let mut fixture = Fixture::new(text,"arrow","() => target()");
            fixture.responses[PREPARE]["result"][0]["range"] = range(text,"() => target() + 1");
            fixture.check(false).await;
        }
    }

    #[tokio::test]
    async fn binding_reconciliation_preserves_source_and_identity_refusals() {
        let text = "function target() { return 1; }\nconst arrow = () => target();\n";
        for case in 0..11 {
            let mut f = Fixture::new(text, "arrow", "() => target()");
            let item = &mut f.responses[PREPARE]["result"][0];
            match case {
                0 => item["uri"] = json!(protocol::path_to_uri(&f.root.join("other.ts"))),
                1 => item["range"] = range(text, "target();"),
                2 => item["range"] = range(text, "() => target();"),
                3 => item["selectionRange"] = range(text, "arro"),
                4 => f.text = text.replace("= ()", "=  ()"),
                5 => f.caller.start_col += 1,
                6 => f.caller.end_line += 1,
                7 => f.caller.kind = EntityKind::Constant,
                8 => f.caller.id = EntityId::new(),
                9 => f.text = text.replace("() =>", "(  =>"),
                10 => f.caller.file_path = "sample.py".into(),
                _ => unreachable!(),
            }
            f.check(false).await;
        }
    }

    #[tokio::test]
    async fn ordinary_function_disjoint_range_remains_invalid() {
        let text = "function target() { return 1; }\nfunction ordinary() { return target(); }\n";
        let f = Fixture::new(text, "ordinary", "{ return target(); }");
        f.check(false).await;
    }

    /// A server started without grammars proves no TypeScript or TSX binding
    /// initializer, the same shapes the grammars prove above, so a caller that
    /// passes none gets a refusal and never a wrong proof.
    #[tokio::test]
    async fn a_server_started_without_grammars_proves_no_binding_initializer() {
        let text = "function target() { return 1; }\nexport const arrow = () => target();\n";
        for file in ["sample.ts", "sample.tsx"] {
            let f = Fixture::in_file(text, "arrow", "() => target()", file);
            f.check_with(Some(kin_grammars()), true).await;
            f.check_with(None, false).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires an installed typescript-language-server and TypeScript"]
    async fn real_typescript_binding_call_hierarchy() {
        let text = "function target() { return 1; }\nexport const arrow = () => target();\n";
        let f = Fixture::new(text, "arrow", "() => target()");
        std::fs::write(f.root.join("sample.ts"), text).unwrap();
        std::fs::write(
            f.root.join("tsconfig.json"),
            r#"{"compilerOptions":{"target":"ES2022"},"include":["*.ts"]}"#,
        )
        .unwrap();
        let server = LspServer::start(
            "typescript-language-server",
            &["--stdio"],
            &f.root,
            None,
            Some(kin_grammars()),
        )
        .await
        .unwrap();
        assert!(server.has_call_hierarchy());
        server
            .client
            .notify(
                "textDocument/didOpen",
                json!({"textDocument":{
            "uri":protocol::path_to_uri(&f.root.join("sample.ts")),"languageId":"typescript",
            "version":1,"text":text}}),
            )
            .await
            .unwrap();
        let answer = enrich_entity_calls(
            &server,
            &f.caller,
            &f.index,
            &f.root,
            Some(&|_| Some(text.into())),
        )
        .await;
        server.shutdown().await.unwrap();
        let relations = answer.unwrap().relations;
        assert!(
            relations
                .iter()
                .any(|r| r.src == GraphNodeId::Entity(f.caller.id)
                    && r.dst == GraphNodeId::Entity(f.target.id)),
            "{relations:?}"
        );
    }
}
