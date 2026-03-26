// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{
    EntityKind, FilePathId, FingerprintAlgorithm, Hash256, LanguageId, ParseState,
    SemanticFingerprint, SourceSpan, Visibility,
};
use sha2::{Digest, Sha256};
use tree_sitter::Tree;

use crate::adapter::{collect_error_ranges, make_parser, LanguageAdapter};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, FileImport, ImportedName, ParseOutput};
use crate::shallow::{extract_shallow, ShallowDecl, ShallowDeclKind, ShallowImport};

pub struct CSharpAdapter;
pub struct RubyAdapter;

macro_rules! impl_shallow_adapter {
    ($ty:ident, $lang:expr, $language_fn:expr, [$($ext:expr),+ $(,)?]) => {
        impl LanguageAdapter for $ty {
            fn language_id(&self) -> LanguageId {
                $lang
            }

            fn file_extensions(&self) -> &[&str] {
                &[$($ext),+]
            }

            fn parse(&self, source: &[u8]) -> Result<Tree> {
                let mut parser = make_parser(&$language_fn)?;
                parser
                    .parse(source, None)
                    .ok_or_else(|| crate::error::ParseError::ParseFailed {
                        file: String::new(),
                        reason: "tree-sitter returned None".into(),
                    })
            }

            fn extract(
                &self,
                tree: &Tree,
                source: &[u8],
                file_id: &FilePathId,
            ) -> Result<ParseOutput> {
                Ok(extract_shallow_backed_output($lang, tree, source, file_id))
            }
        }
    };
}

impl_shallow_adapter!(
    CSharpAdapter,
    LanguageId::CSharp,
    tree_sitter_c_sharp::LANGUAGE,
    ["cs"]
);
impl_shallow_adapter!(
    RubyAdapter,
    LanguageId::Ruby,
    tree_sitter_ruby::LANGUAGE,
    ["rb"]
);

fn extract_shallow_backed_output(
    language: LanguageId,
    tree: &Tree,
    source: &[u8],
    file_id: &FilePathId,
) -> ParseOutput {
    let error_ranges = collect_error_ranges(tree);
    let parse_state = if error_ranges.is_empty() {
        ParseState::Valid
    } else {
        ParseState::Incomplete { error_ranges }
    };

    let shallow = extract_shallow(tree, source, file_id, Some(&language.to_string()));
    let entities = shallow
        .declarations
        .iter()
        .filter_map(|decl| shallow_decl_to_entity(language, file_id, source, decl))
        .collect();
    let relations = shallow
        .imports
        .iter()
        .map(|imp| ExtractedRelation {
            kind: kin_model::RelationKind::Imports,
            src_name: file_id.to_string(),
            dst_name: imp.raw_path.clone(),
            import_source: None,
        })
        .collect();
    let imports = shallow
        .imports
        .iter()
        .map(shallow_import_to_file_import)
        .collect();

    ParseOutput {
        entities,
        relations,
        imports,
        tests: Vec::new(),
        parse_state,
    }
}

fn shallow_decl_to_entity(
    language: LanguageId,
    file_id: &FilePathId,
    source: &[u8],
    decl: &ShallowDecl,
) -> Option<ExtractedEntity> {
    let kind = match decl.kind {
        ShallowDeclKind::FunctionLike => EntityKind::Function,
        ShallowDeclKind::TypeLike => EntityKind::Class,
        ShallowDeclKind::ModuleLike => EntityKind::Module,
        ShallowDeclKind::ConstantLike => EntityKind::Constant,
        ShallowDeclKind::Unknown => return None,
    };

    let signature = format!("{} {}", decl.kind, decl.name);
    Some(ExtractedEntity {
        kind,
        name: decl.name.clone(),
        signature: signature.clone(),
        visibility: infer_visibility(language, decl),
        doc_summary: None,
        fingerprint: shallow_decl_fingerprint(language, decl, &signature),
        span: span_from_shallow_decl(file_id, source, decl),
    })
}

fn infer_visibility(language: LanguageId, decl: &ShallowDecl) -> Visibility {
    match language {
        LanguageId::Go if decl.name.chars().next().is_some_and(|c| c.is_uppercase()) => {
            Visibility::Public
        }
        LanguageId::CSharp | LanguageId::Java | LanguageId::Ruby | LanguageId::Php | LanguageId::Swift | LanguageId::Kotlin => {
            Visibility::Public
        }
        _ => Visibility::Internal,
    }
}

fn shallow_decl_fingerprint(
    language: LanguageId,
    decl: &ShallowDecl,
    signature: &str,
) -> SemanticFingerprint {
    SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash: stable_hash(&format!(
            "ast:{language}:{:?}:{}:{}:{}",
            decl.kind, decl.name, decl.start_line, decl.end_line
        )),
        signature_hash: stable_hash(&format!("sig:{language}:{signature}")),
        behavior_hash: stable_hash(&format!(
            "behavior:{language}:{:?}:{}",
            decl.kind, decl.name
        )),
        stability_score: 0.55,
    }
}

fn stable_hash(input: &str) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256::from_bytes(bytes)
}

fn span_from_shallow_decl(file_id: &FilePathId, source: &[u8], decl: &ShallowDecl) -> SourceSpan {
    let line_starts = line_start_offsets(source);
    let start_line = decl.start_line as usize;
    let end_line = decl.end_line as usize;
    let start_byte = *line_starts.get(start_line).unwrap_or(&0);
    let mut end_byte = *line_starts.get(end_line + 1).unwrap_or(&source.len());
    if end_byte <= start_byte {
        end_byte = source
            .len()
            .max(start_byte + usize::from(!source.is_empty()));
    }

    SourceSpan {
        file: file_id.clone(),
        start_byte,
        end_byte,
        start_line: decl.start_line,
        start_col: 0,
        end_line: decl.end_line,
        end_col: end_byte.saturating_sub(start_byte) as u32,
    }
}

fn line_start_offsets(source: &[u8]) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in source.iter().enumerate() {
        if *byte == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

fn shallow_import_to_file_import(imp: &ShallowImport) -> FileImport {
    let specifiers = infer_import_local_name(&imp.raw_path)
        .map(|name| {
            vec![ImportedName {
                local_name: name,
                original_name: None,
                is_default: false,
            }]
        })
        .unwrap_or_default();

    FileImport {
        module_path: imp.raw_path.clone(),
        specifiers,
    }
}

fn infer_import_local_name(raw_path: &str) -> Option<String> {
    let trimmed = raw_path.trim().trim_matches(|c| c == '"' || c == '\'');
    if trimmed.is_empty() {
        return None;
    }

    let last_segment = trimmed
        .rsplit(['/', '\\', ':'])
        .next()
        .unwrap_or(trimmed)
        .rsplit('.')
        .next()
        .unwrap_or(trimmed)
        .trim_matches('*')
        .trim();

    if last_segment.is_empty() {
        None
    } else {
        Some(last_segment.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_names<A: LanguageAdapter>(adapter: &A, file: &str, source: &[u8]) -> Vec<String> {
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new(file);
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        output.entities.into_iter().map(|e| e.name).collect()
    }

    #[test]
    fn parse_csharp_extracts_class_and_method_like_decl() {
        let names = parse_names(
            &CSharpAdapter,
            "Basic.cs",
            b"using System;\npublic class Greeter { public void SayHi() {} }\n",
        );
        assert!(names.contains(&"Greeter".to_string()));
    }

    #[test]
    fn parse_ruby_extracts_class_and_method() {
        let names = parse_names(
            &RubyAdapter,
            "basic.rb",
            b"class Greeter\n  def call(name)\n    puts name\n  end\nend\n\ndef helper(name)\n  Greeter.new.call(name)\nend\n",
        );
        assert!(names.contains(&"Greeter".to_string()));
        assert!(names.contains(&"helper".to_string()));
    }
}
