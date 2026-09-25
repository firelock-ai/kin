// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Guarded creation and removal of declarations.
//!
//! Creation has two forms. Anchored creation places a function relative to a
//! real declaration, bound to that declaration's source base. Unit-addressed
//! creation names a source unit by language identity and is bound to the
//! repository base the caller last observed; it is how the first declaration
//! of an empty repository, and every Go declaration kind, is created. Neither
//! form accepts a path or an offset.

use serde::{Deserialize, Serialize};

use crate::source_base::EntitySourceBase;
use crate::source_unit::{DeclarationKind, ImportSpec, RepositoryBase, SourceUnit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityPlacement {
    SiblingAfter,
    NewSourceUnit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityCreate {
    /// Anchored form: the actual independent anchor's unchanged source base.
    /// This does not grant authority to rewrite its containing artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_base: Option<EntitySourceBase>,
    /// Anchored form: where the function goes relative to its anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<EntityPlacement>,
    /// Unit form: the repository instant the caller last observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_base: Option<RepositoryBase>,
    /// Unit form: the source unit, by language identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<SourceUnit>,
    pub name: String,
    pub kind: DeclarationKind,
    pub body: String,
    /// Unit form: imports the declaration needs, merged into the unit's block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<ImportSpec>,
}

/// Which of the two creation forms a payload takes.
#[derive(Debug, Clone, Copy)]
pub enum CreateForm<'a> {
    Anchored {
        source_base: &'a EntitySourceBase,
        placement: EntityPlacement,
    },
    Unit {
        repository_base: &'a RepositoryBase,
        unit: &'a SourceUnit,
    },
}

const CREATE_FORMS: &str = "EntityCreate takes one of two forms: addressed to a unit, with \
repository_base and unit (any supported declaration kind, and the only form for an empty \
repository), or anchored, with the source_base of a current function and placement";

fn is_ascii_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

impl EntityCreate {
    pub fn form(&self) -> Result<CreateForm<'_>, String> {
        match (
            &self.source_base,
            self.placement,
            &self.repository_base,
            &self.unit,
        ) {
            (Some(source_base), Some(placement), None, None) => Ok(CreateForm::Anchored {
                source_base,
                placement,
            }),
            (None, None, Some(repository_base), Some(unit)) => Ok(CreateForm::Unit {
                repository_base,
                unit,
            }),
            _ => Err(CREATE_FORMS.into()),
        }
    }

    /// The anchor's source base, for the anchored form.
    pub fn anchor(&self) -> Option<(&EntitySourceBase, EntityPlacement)> {
        match self.form() {
            Ok(CreateForm::Anchored {
                source_base,
                placement,
            }) => Some((source_base, placement)),
            _ => None,
        }
    }

    /// The repository base and unit, for the unit form.
    pub fn unit_target(&self) -> Option<(&RepositoryBase, &SourceUnit)> {
        match self.form() {
            Ok(CreateForm::Unit {
                repository_base,
                unit,
            }) => Some((repository_base, unit)),
            _ => None,
        }
    }

    /// The `target` an operation carrying this payload must name: the anchor's
    /// UUID for the anchored form, the declared name for the unit form.
    pub fn expected_target(&self) -> Option<String> {
        match self.form().ok()? {
            CreateForm::Anchored { source_base, .. } => Some(source_base.entity_id.to_string()),
            CreateForm::Unit { .. } => Some(self.name.clone()),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.body.trim().is_empty() {
            return Err("EntityCreate requires the exact nonempty body of one declaration".into());
        }
        match self.form()? {
            CreateForm::Anchored { source_base, .. } => {
                source_base.validate()?;
                if self.kind != DeclarationKind::Function {
                    return Err(
                        "anchored EntityCreate creates top-level functions in Rust, Python and \
                         Go; create other declaration kinds addressed to a unit, with \
                         repository_base and unit"
                            .into(),
                    );
                }
                if !self.imports.is_empty() {
                    return Err(
                        "anchored EntityCreate does not manage imports; address the \
                         unit, with repository_base and unit, to add imports with the \
                         declaration"
                            .into(),
                    );
                }
                if !is_ascii_identifier(&self.name) {
                    return Err(
                        "EntityCreate name must be one ASCII identifier, never a path".into(),
                    );
                }
                Ok(())
            }
            CreateForm::Unit {
                repository_base,
                unit,
            } => {
                repository_base.validate()?;
                unit.validate()?;
                crate::source_unit::validate_create_imports(unit, &self.imports)?;
                match unit {
                    SourceUnit::Go { .. } => {
                        let expected = self.kind.go()?;
                        let parsed = kin_parser::go_unit::parse_declaration(&self.body)
                            .map_err(|error| format!("EntityCreate body: {error}"))?;
                        if parsed.kind != expected {
                            return Err(format!(
                                "EntityCreate kind {} does not match its body, which declares a \
                                 Go {}",
                                expected.label(),
                                parsed.kind.label()
                            ));
                        }
                        // A blank var or const (`var _ Getter = (*Store)(nil)`) is
                        // named `_` by the caller; its entity takes the derived name
                        // the reply reports.
                        let blank = self.name == "_"
                            && parsed
                                .names
                                .first()
                                .is_some_and(|name| name.starts_with("_ "));
                        if parsed.names.first() != Some(&self.name) && !blank {
                            return Err(format!(
                                "EntityCreate name {:?} must be the body's declared name {:?}: \
                                 Name, Receiver.Method for a method, the first name of a \
                                 grouped const or var, or _ for a blank var or const",
                                self.name,
                                parsed.names.first().cloned().unwrap_or_default()
                            ));
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// Deterministic projection choice shared with intent admission. Its inputs come
/// from the authoritative anchor, never from a caller-supplied file locator.
pub fn generated_source_path(
    origin: &kin_model::FilePathId,
    language: kin_model::LanguageId,
    name: &str,
) -> Result<kin_model::RepoPath, String> {
    let mut chars = name.bytes();
    if !chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err("new source unit requires one semantic identifier".into());
    }
    let extension = match language {
        kin_model::LanguageId::Rust => "rs",
        kin_model::LanguageId::Python => "py",
        kin_model::LanguageId::Go => "go",
        _ => return Err("unsupported lifecycle language".into()),
    };
    let parent = std::path::Path::new(&origin.0)
        .parent()
        .ok_or("anchor has no owner directory")?;
    let generated = parent.join(format!("{name}.{extension}"));
    let path =
        kin_model::RepoPath::from_utf8(generated.to_str().ok_or("non-UTF8 owner")?.to_owned())
            .map_err(|e| e.to_string())?;
    kin_core::validate_source_paths([&path]).map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRemove {
    pub source_base: EntitySourceBase,
}

impl EntityRemove {
    pub fn validate(&self) -> Result<(), String> {
        self.source_base.validate()
    }
}

pub fn entity_create_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"object",
        "description":"Create one declaration, in one of two forms, with no path or offset. Addressed to a unit (repository_base and unit): the form for an empty repository and for every Go declaration kind. Kin derives the unit's file, writes its package clause, places the declaration (a method directly after its receiver type or that type's last method, anything else at the end of the unit) and merges imports into the unit's one import block. The operation's target is the declared name. Anchored (source_base and placement): one top-level function in Rust, Python or Go beside a current function, whose UUID is the target. Occupied names, ambiguous placement and stale bases refuse without publication.",
        "properties":{
            "repository_base":crate::source_unit::repository_base_schema(),
            "unit":crate::source_unit::source_unit_schema(),
            "source_base":crate::source_base::source_base_schema(),
            "placement":{"type":"string","enum":["sibling_after","new_source_unit"]},
            "name":{"type":"string","minLength":1,"description":"The declared name as the graph names it: Name, Receiver.Method for a method, the first name of a grouped const or var, or _ for a blank var or const such as var _ Getter = (*Store)(nil), whose entity is named after the assertion (_ Getter = (*Store)(nil))."},
            "kind":{"type":"string","enum":crate::source_unit::DeclarationKind::WIRE_NAMES,"description":"Go admits function, method, struct, interface, type, const and var; anchored creation admits function. The graph kinds class, type_alias, constant and static_var are accepted as synonyms."},
            "body":{"type":"string","minLength":1,"description":"Exactly the declaration's source, optionally led by its doc comment: no package clause, imports or sibling declarations."},
            "imports":{"type":"array","items":crate::source_unit::import_spec_schema(),"description":"Unit form: import paths the declaration needs, added to the unit's import block."}
        },
        "required":["name","kind","body"],
        "oneOf":[{"required":["repository_base","unit"]},{"required":["source_base","placement"]}],
        "additionalProperties":false
    })
}

pub fn entity_remove_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"object",
        "description":"Remove one source-bound top-level leaf function in Rust, Python or Go, preserving its artifact and siblings. No whole-file removal is admitted.",
        "properties":{"source_base":crate::source_base::source_base_schema()},
        "required":["source_base"],
        "additionalProperties":false
    })
}

/// The belt's compact forms. They advertise less than the handler accepts (an
/// import with an alias, the full base schemas) and keep every rule a caller
/// needs to build a valid operation.
pub(crate) fn compact_schema(create: bool) -> serde_json::Value {
    let source_base = serde_json::json!({"type":"object","description":"Unchanged source_base from a current get_entity_source read."});
    if !create {
        let mut schema = entity_remove_schema();
        schema["properties"]["source_base"] = source_base;
        return schema;
    }
    serde_json::json!({
        "type":"object",
        "description":"Unit form (empty repository, any Go kind): repository_base and unit, target the name. Anchored form (functions): source_base and placement, target the anchor UUID.",
        "properties":{
            "repository_base":COMPACT_REPOSITORY_BASE.clone(),
            "unit":COMPACT_UNIT.clone(),
            "source_base":source_base,
            "placement":{"type":"string","enum":["sibling_after","new_source_unit"]},
            "name":{"type":"string","description":"Name, or Receiver.Method."},
            "kind":{"type":"string","enum":crate::source_unit::DeclarationKind::WIRE_NAMES},
            "body":{"type":"string","minLength":1,"description":"The declaration only: no package clause or imports."},
            "imports":{"type":"array","items":{"type":"string"},"description":"Import paths it needs."}
        },
        "required":["name","kind","body"],
        "additionalProperties":false
    })
}

static COMPACT_REPOSITORY_BASE: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(
    || serde_json::json!({"type":"object","description":"Unchanged repository_base from session, status or the last mutate."}),
);

static COMPACT_UNIT: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(
    || serde_json::json!({"type":"object","description":"{language:\"go\", package:\".\" or \"internal/store\", name: package name, role:\"source\" or \"test\"}"}),
);

pub(crate) fn compact_unit_imports_schema() -> serde_json::Value {
    serde_json::json!({
        "type":"object",
        "description":"Add or remove imports on a unit; Kin writes its import block. Target the package name.",
        "properties":{
            "repository_base":COMPACT_REPOSITORY_BASE.clone(),
            "unit":COMPACT_UNIT.clone(),
            "add":{"type":"array","items":{"type":"string"}},
            "remove":{"type":"array","items":{"type":"string"}}
        },
        "required":["repository_base","unit"],
        "additionalProperties":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_base::{SourceBaseContext, SourceBaseSchema};

    fn base() -> EntitySourceBase {
        EntitySourceBase {
            schema: SourceBaseSchema::V1,
            context: SourceBaseContext {
                repository_id: "lifecycle-test".into(),
                workspace_id: uuid::Uuid::new_v4().to_string(),
                workspace_generation: 1,
                workspace_head_hash: "a".repeat(64),
                workspace_tree_hash: "b".repeat(64),
            },
            entity_id: kin_model::EntityId::new(),
            artifact_id: kin_model::ArtifactId::new(),
            source_blob_hash: "c".repeat(64),
            start_byte: 0,
            end_byte: 12,
            body_hash: "d".repeat(64),
        }
    }

    fn anchored(body: &str) -> EntityCreate {
        EntityCreate {
            source_base: Some(base()),
            placement: Some(EntityPlacement::SiblingAfter),
            repository_base: None,
            unit: None,
            name: "added".into(),
            kind: DeclarationKind::Function,
            body: body.into(),
            imports: Vec::new(),
        }
    }

    fn repository_base() -> RepositoryBase {
        RepositoryBase {
            schema: crate::source_unit::RepositoryBaseSchema::V1,
            context: base().context,
        }
    }

    /// An operation as a caller sends it: absent fields omitted, not null.
    fn wire(op: &crate::McpMutationOperation) -> serde_json::Value {
        let mut value = serde_json::to_value(op).unwrap();
        let fields = value.as_object_mut().unwrap();
        fields.retain(|_, field| !field.is_null());
        value
    }

    fn unit_create(name: &str, kind: DeclarationKind, body: &str) -> crate::McpMutationOperation {
        crate::McpMutationOperation {
            verb: "create".into(),
            target: name.into(),
            payload: Some(crate::McpMutationPayload::EntityCreate(EntityCreate {
                source_base: None,
                placement: None,
                repository_base: Some(repository_base()),
                unit: Some(SourceUnit::Go {
                    package: "internal/store".into(),
                    name: "store".into(),
                    role: crate::source_unit::UnitRole::Source,
                }),
                name: name.into(),
                kind,
                body: body.into(),
                imports: vec![ImportSpec::Path("sync".into())],
            })),
            body: None,
            destination: None,
            description: "create a declaration".into(),
        }
    }

    #[test]
    fn unit_creation_is_addressed_by_language_identity_and_closed() {
        for (name, kind, body) in [
            (
                "Store",
                DeclarationKind::Struct,
                "type Store struct {\n\tmu sync.Mutex\n}",
            ),
            (
                "Store.Len",
                DeclarationKind::Method,
                "func (s *Store) Len() int { return 0 }",
            ),
            (
                "Getter",
                DeclarationKind::Interface,
                "type Getter interface{ Get(string) string }",
            ),
            (
                "Limit",
                DeclarationKind::Const,
                "const (\n\tLimit = 10\n\tFloor = 1\n)",
            ),
            (
                "ErrMissing",
                DeclarationKind::Var,
                "var ErrMissing = errors.New(\"missing\")",
            ),
            ("ID", DeclarationKind::Type, "type ID string"),
            (
                "New",
                DeclarationKind::Function,
                "// New builds one.\nfunc New() *Store { return &Store{} }",
            ),
            ("_", DeclarationKind::Var, "var _ Getter = (*Store)(nil)"),
        ] {
            let op = unit_create(name, kind, body);
            crate::session::validate_semantic_operations(std::slice::from_ref(&op))
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let wire = wire(&op);
            assert_eq!(
                crate::session::parse_staged_operations(&serde_json::json!([wire]))
                    .unwrap()
                    .len(),
                1
            );
        }
        let refused = |op: crate::McpMutationOperation| {
            crate::session::validate_semantic_operations(&[op]).unwrap_err()
        };
        // The target names the declaration, never a file.
        let mut op = unit_create("Store", DeclarationKind::Struct, "type Store struct{}");
        op.target = "internal/store/store.go".into();
        assert!(refused(op).contains("target"));
        // The name and kind must be the body's own.
        assert!(refused(unit_create(
            "Other",
            DeclarationKind::Struct,
            "type Store struct{}"
        ))
        .contains("declared name"));
        assert!(refused(unit_create(
            "Store",
            DeclarationKind::Interface,
            "type Store struct{}"
        ))
        .contains("does not match"));
        assert!(refused(unit_create(
            "Len",
            DeclarationKind::Method,
            "func (s *Store) Len() int { return 0 }"
        ))
        .contains("Receiver.Method"));
        // Kin owns the package clause and the import block.
        assert!(refused(unit_create(
            "F",
            DeclarationKind::Function,
            "package store\nfunc F() {}"
        ))
        .contains("package clause"));
        assert!(refused(unit_create(
            "F",
            DeclarationKind::Function,
            "import \"fmt\"\nfunc F() {}"
        ))
        .contains("import"));
        // A path-shaped unit is refused.
        let mut op = unit_create("F", DeclarationKind::Function, "func F() {}");
        let Some(crate::McpMutationPayload::EntityCreate(create)) = op.payload.as_mut() else {
            unreachable!()
        };
        create.unit = Some(SourceUnit::Go {
            package: "internal/store/store.go".into(),
            name: "store".into(),
            role: crate::source_unit::UnitRole::Source,
        });
        assert!(refused(op).contains("file"));
        // Both forms at once, or neither, is refused.
        let mut op = unit_create("F", DeclarationKind::Function, "func F() {}");
        let Some(crate::McpMutationPayload::EntityCreate(create)) = op.payload.as_mut() else {
            unreachable!()
        };
        create.source_base = Some(base());
        assert!(refused(op).contains("two forms"));
        // An unknown kind and a smuggled path field fail to decode.
        let mut bad = wire(&unit_create("F", DeclarationKind::Function, "func F() {}"));
        bad["payload"]["EntityCreate"]["kind"] = "module".into();
        assert!(crate::session::parse_staged_operations(&serde_json::json!([bad])).is_err());
        let mut bad = wire(&unit_create("F", DeclarationKind::Function, "func F() {}"));
        bad["payload"]["EntityCreate"]["path"] = "main.go".into();
        assert!(crate::session::parse_staged_operations(&serde_json::json!([bad])).is_err());
        // Anchored creation stays function-only and import-free.
        let mut create = anchored("fn added() {}");
        create.kind = DeclarationKind::Struct;
        assert!(create
            .validate()
            .unwrap_err()
            .contains("addressed to a unit"));
        let mut create = anchored("fn added() {}");
        create.imports = vec![ImportSpec::Path("std".into())];
        assert!(create.validate().unwrap_err().contains("imports"));
    }

    #[test]
    fn unit_imports_are_closed_and_refuse_ambiguous_changes() {
        let unit = SourceUnit::Go {
            package: ".".into(),
            name: "main".into(),
            role: crate::source_unit::UnitRole::Source,
        };
        let imports = |add: Vec<&str>, remove: Vec<&str>| crate::source_unit::UnitImports {
            repository_base: repository_base(),
            unit: unit.clone(),
            add: add
                .into_iter()
                .map(|p| ImportSpec::Path(p.into()))
                .collect(),
            remove: remove
                .into_iter()
                .map(|p| ImportSpec::Path(p.into()))
                .collect(),
        };
        let op = |payload: crate::source_unit::UnitImports| crate::McpMutationOperation {
            verb: "update".into(),
            target: "main".into(),
            payload: Some(crate::McpMutationPayload::UnitImports(payload)),
            body: None,
            destination: None,
            description: "manage imports".into(),
        };
        crate::session::validate_semantic_operations(&[op(imports(vec!["fmt"], vec!["os"]))])
            .unwrap();
        for bad in [
            imports(vec![], vec![]),
            imports(vec!["fmt"], vec!["fmt"]),
            imports(vec!["fmt", "fmt"], vec![]),
            imports(vec!["../x"], vec![]),
            imports(vec!["\"fmt\""], vec![]),
        ] {
            assert!(crate::session::validate_semantic_operations(&[op(bad)]).is_err());
        }
        let mut wrong_target = op(imports(vec!["fmt"], vec![]));
        wrong_target.target = "main.go".into();
        assert!(crate::session::validate_semantic_operations(&[wrong_target]).is_err());
        let mut body = op(imports(vec!["fmt"], vec![]));
        body.body = Some("import \"fmt\"".into());
        assert!(crate::session::validate_semantic_operations(&[body]).is_err());
    }

    #[test]
    fn entity_lifecycle_shapes_are_closed_and_source_bound() {
        let create = anchored("fn added() {}");
        let anchor = create.source_base.clone().unwrap();
        let mut operation = crate::McpMutationOperation {
            verb: "create".into(),
            target: anchor.entity_id.to_string(),
            payload: Some(crate::McpMutationPayload::EntityCreate(create.clone())),
            body: None,
            destination: None,
            description: "one declaration".into(),
        };
        crate::session::validate_semantic_operations(&[operation.clone()]).unwrap();
        operation.target = "src/lib.rs".into();
        assert!(crate::session::validate_semantic_operations(&[operation.clone()]).is_err());
        operation.target = anchor.entity_id.to_string();
        for forbidden in ["body", "destination"] {
            let mut value = serde_json::to_value(&operation).unwrap();
            value.as_object_mut().unwrap().remove("body");
            value.as_object_mut().unwrap().remove("destination");
            value[forbidden] = serde_json::Value::Null;
            assert!(crate::session::parse_staged_operations(&serde_json::json!([value])).is_err());
        }
        let mut value = serde_json::to_value(&create).unwrap();
        value["path"] = "evil.py".into();
        assert!(serde_json::from_value::<EntityCreate>(value).is_err());
        operation.verb = "remove".into();
        operation.payload = Some(crate::McpMutationPayload::EntityRemove(EntityRemove {
            source_base: anchor,
        }));
        crate::session::validate_semantic_operations(&[operation.clone()]).unwrap();
        operation.body = Some("unrequested source".into());
        assert!(crate::session::validate_semantic_operations(&[operation]).is_err());
    }

    #[test]
    fn entity_lifecycle_creation_retains_truncated_body_refusal() {
        let mut create = anchored("def added():\n    pass # ... [truncated]");
        let op = |create: EntityCreate| crate::McpMutationOperation {
            verb: "create".into(),
            target: create.expected_target().unwrap(),
            payload: Some(crate::McpMutationPayload::EntityCreate(create)),
            body: None,
            destination: None,
            description: "one declaration".into(),
        };
        assert!(crate::handlers::sessions::reject_truncated_bodies(&[op(create.clone())]).is_err());
        create.body = "def added():\n    return '[truncated]'".into();
        crate::handlers::sessions::reject_truncated_bodies(&[op(create)]).unwrap();
    }

    #[test]
    fn entity_lifecycle_projection_names_cannot_supply_paths() {
        let origin = kin_model::FilePathId::new("pkg/source.py");
        assert_eq!(
            generated_source_path(&origin, kin_model::LanguageId::Python, "added")
                .unwrap()
                .to_string(),
            "pkg/added.py"
        );
        for name in ["../escape", "foo/bar", "", "a.py", "a\\b"] {
            assert!(generated_source_path(&origin, kin_model::LanguageId::Python, name).is_err());
        }
        assert!(
            generated_source_path(&origin, kin_model::LanguageId::JavaScript, "added").is_err()
        );
    }
}
