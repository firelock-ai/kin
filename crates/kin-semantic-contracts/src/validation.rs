// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::contract::ContractKind;
use kin_model::EntityId;
use serde::{Deserialize, Serialize};

/// A detected breaking change in a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractBreakage {
    pub contract_id: EntityId,
    pub kind: BreakageKind,
    pub description: String,
    pub affected_consumers: Vec<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakageKind {
    RemovedEndpoint,
    RemovedField,
    TypeChanged,
    RequiredFieldAdded,
    EnumVariantRemoved,
}

/// Compare old and new schema content for breaking changes.
/// Returns detected breakages (empty vec = no breaking changes).
pub fn detect_breaking_changes(
    old_schema: &str,
    new_schema: &str,
    kind: ContractKind,
    contract_id: EntityId,
) -> Vec<ContractBreakage> {
    // Try JSON-based structural comparison first
    if let (Ok(old_val), Ok(new_val)) = (
        serde_json::from_str::<serde_json::Value>(old_schema),
        serde_json::from_str::<serde_json::Value>(new_schema),
    ) {
        return detect_json_breakages(&old_val, &new_val, contract_id, kind);
    }

    // Fall back to line-based analysis for non-JSON schemas (YAML, proto, GraphQL, SQL)
    detect_line_based_breakages(old_schema, new_schema, contract_id, kind)
}

/// Structural JSON comparison for OpenAPI JSON, JSON Schema, etc.
fn detect_json_breakages(
    old: &serde_json::Value,
    new: &serde_json::Value,
    contract_id: EntityId,
    kind: ContractKind,
) -> Vec<ContractBreakage> {
    let mut breakages = Vec::new();
    diff_json_values(old, new, &mut Vec::new(), &mut breakages, contract_id, kind);
    breakages
}

fn diff_json_values(
    old: &serde_json::Value,
    new: &serde_json::Value,
    path: &mut Vec<String>,
    breakages: &mut Vec<ContractBreakage>,
    contract_id: EntityId,
    kind: ContractKind,
) {
    use serde_json::Value;

    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            // Check for removed keys
            for key in old_map.keys() {
                if !new_map.contains_key(key) {
                    path.push(key.clone());
                    let path_str = path.join(".");

                    let breakage_kind = classify_removed_key(&path_str, kind);
                    breakages.push(ContractBreakage {
                        contract_id,
                        kind: breakage_kind,
                        description: format!("removed: {path_str}"),
                        affected_consumers: Vec::new(),
                    });
                    path.pop();
                }
            }

            // Check for new required fields
            if let (Some(Value::Array(old_req)), Some(Value::Array(new_req))) =
                (old_map.get("required"), new_map.get("required"))
            {
                for item in new_req {
                    if !old_req.contains(item) {
                        if let Some(field_name) = item.as_str() {
                            breakages.push(ContractBreakage {
                                contract_id,
                                kind: BreakageKind::RequiredFieldAdded,
                                description: format!(
                                    "new required field: {field_name} at {}",
                                    path.join(".")
                                ),
                                affected_consumers: Vec::new(),
                            });
                        }
                    }
                }
            }

            // Recurse into shared keys
            for (key, old_val) in old_map {
                if let Some(new_val) = new_map.get(key) {
                    path.push(key.clone());
                    diff_json_values(old_val, new_val, path, breakages, contract_id, kind);
                    path.pop();
                }
            }
        }
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            // For enum-like arrays, check for removed variants
            if is_enum_array(old, path) {
                for item in old_arr {
                    if !new_arr.contains(item) {
                        if let Some(name) = item.as_str() {
                            breakages.push(ContractBreakage {
                                contract_id,
                                kind: BreakageKind::EnumVariantRemoved,
                                description: format!(
                                    "enum variant removed: {name} at {}",
                                    path.join(".")
                                ),
                                affected_consumers: Vec::new(),
                            });
                        }
                    }
                }
            }
            // For non-enum arrays, recurse into matching indices
            let min_len = old_arr.len().min(new_arr.len());
            for i in 0..min_len {
                path.push(format!("[{i}]"));
                diff_json_values(&old_arr[i], &new_arr[i], path, breakages, contract_id, kind);
                path.pop();
            }
        }
        // Type changed (e.g., string -> number, object -> string, etc.)
        _ if std::mem::discriminant(old) != std::mem::discriminant(new) => {
            let path_str = if path.is_empty() {
                "<root>".to_string()
            } else {
                path.join(".")
            };
            breakages.push(ContractBreakage {
                contract_id,
                kind: BreakageKind::TypeChanged,
                description: format!(
                    "type changed at {path_str}: {} -> {}",
                    json_type_name(old),
                    json_type_name(new)
                ),
                affected_consumers: Vec::new(),
            });
        }
        // For "type" fields in JSON Schema, detect type string changes
        _ if path.last().map(|s| s.as_str()) == Some("type")
            && old.is_string()
            && new.is_string()
            && old != new =>
        {
            let path_str = path.join(".");
            breakages.push(ContractBreakage {
                contract_id,
                kind: BreakageKind::TypeChanged,
                description: format!(
                    "type changed at {path_str}: {} -> {}",
                    old.as_str().unwrap_or("?"),
                    new.as_str().unwrap_or("?")
                ),
                affected_consumers: Vec::new(),
            });
        }
        _ => {}
    }
}

/// Classify a removed key based on its path and contract kind.
fn classify_removed_key(path: &str, kind: ContractKind) -> BreakageKind {
    match kind {
        ContractKind::OpenApi if path.starts_with("paths.") => BreakageKind::RemovedEndpoint,
        _ => BreakageKind::RemovedField,
    }
}

/// Check if an array looks like an enum definition (parent key is "enum").
fn is_enum_array(_val: &serde_json::Value, path: &[String]) -> bool {
    path.last().map(|s| s.as_str()) == Some("enum")
}

fn json_type_name(val: &serde_json::Value) -> &'static str {
    match val {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Line-based fallback for YAML, protobuf, GraphQL, SQL schemas.
fn detect_line_based_breakages(
    old_schema: &str,
    new_schema: &str,
    contract_id: EntityId,
    kind: ContractKind,
) -> Vec<ContractBreakage> {
    let mut breakages = Vec::new();

    let old_defs = extract_definitions(old_schema, kind);
    let new_defs = extract_definitions(new_schema, kind);

    for def in &old_defs {
        if !new_defs.iter().any(|d| d.name == def.name) {
            let breakage_kind = match def.def_type {
                DefinitionType::Endpoint => BreakageKind::RemovedEndpoint,
                DefinitionType::Field => BreakageKind::RemovedField,
                DefinitionType::EnumVariant => BreakageKind::EnumVariantRemoved,
                DefinitionType::Type => BreakageKind::RemovedField,
            };
            breakages.push(ContractBreakage {
                contract_id,
                kind: breakage_kind,
                description: format!("removed {}: {}", def.def_type_label(), def.name),
                affected_consumers: Vec::new(),
            });
        }
    }

    breakages
}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum DefinitionType {
    Endpoint,
    Field,
    EnumVariant,
    Type,
}

#[derive(Debug)]
struct Definition {
    name: String,
    def_type: DefinitionType,
}

impl Definition {
    fn def_type_label(&self) -> &'static str {
        match self.def_type {
            DefinitionType::Endpoint => "endpoint",
            DefinitionType::Field => "field",
            DefinitionType::EnumVariant => "enum variant",
            DefinitionType::Type => "type",
        }
    }
}

/// Extract named definitions from a schema based on its kind.
fn extract_definitions(content: &str, kind: ContractKind) -> Vec<Definition> {
    match kind {
        ContractKind::OpenApi => extract_yaml_openapi_defs(content),
        ContractKind::Protobuf => extract_proto_defs(content),
        ContractKind::GraphQL => extract_graphql_defs(content),
        ContractKind::DbSchema => extract_sql_defs(content),
        _ => extract_generic_defs(content),
    }
}

/// Extract endpoint paths and definition names from YAML OpenAPI.
fn extract_yaml_openapi_defs(content: &str) -> Vec<Definition> {
    let mut defs = Vec::new();
    let mut in_paths = false;

    for line in content.lines() {
        let trimmed = line.trim();
        // Top-level keys
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_paths = trimmed.starts_with("paths:");
        }
        // Path entries (indented once under paths:)
        if in_paths && !trimmed.is_empty() && line.starts_with("  ") && !line.starts_with("    ") {
            let name = trimmed.trim_end_matches(':');
            if name.starts_with('/') {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Endpoint,
                });
            }
        }
    }
    defs
}

/// Extract message and field names from protobuf.
fn extract_proto_defs(content: &str) -> Vec<Definition> {
    let mut defs = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("message ") {
            let name = trimmed
                .trim_start_matches("message ")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Type,
                });
            }
        } else if trimmed.starts_with("service ") {
            let name = trimmed
                .trim_start_matches("service ")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Type,
                });
            }
        } else if trimmed.starts_with("rpc ") {
            let name = trimmed
                .trim_start_matches("rpc ")
                .split('(')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Endpoint,
                });
            }
        } else if trimmed.starts_with("enum ") {
            let name = trimmed
                .trim_start_matches("enum ")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Type,
                });
            }
        }
    }
    defs
}

/// Extract type definitions from GraphQL schema.
fn extract_graphql_defs(content: &str) -> Vec<Definition> {
    let mut defs = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        for keyword in &[
            "type ",
            "input ",
            "enum ",
            "interface ",
            "union ",
            "scalar ",
        ] {
            if trimmed.starts_with(keyword) {
                let rest = trimmed.trim_start_matches(keyword);
                let name = rest
                    .split(|c: char| c.is_whitespace() || c == '{' || c == '@')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !name.is_empty() {
                    let def_type = DefinitionType::Type;
                    defs.push(Definition {
                        name: name.to_string(),
                        def_type,
                    });
                }
            }
        }
    }
    defs
}

/// Extract table and column names from SQL.
fn extract_sql_defs(content: &str) -> Vec<Definition> {
    let mut defs = Vec::new();
    let upper = content.to_uppercase();

    for line in upper.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("CREATE TABLE") {
            // Extract table name
            let rest = trimmed.trim_start_matches("CREATE TABLE").trim();
            let rest = rest.trim_start_matches("IF NOT EXISTS").trim();
            let name = rest
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Type,
                });
            }
        }
    }
    defs
}

/// Generic line-based extraction for event schemas etc.
fn extract_generic_defs(content: &str) -> Vec<Definition> {
    let mut defs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Look for key definitions like `"fieldName":` or `fieldName:`
        if let Some(name) = trimmed.strip_suffix(':') {
            let name = name.trim_matches('"').trim();
            if !name.is_empty() && !name.contains(' ') {
                defs.push(Definition {
                    name: name.to_string(),
                    def_type: DefinitionType::Field,
                });
            }
        }
    }
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_contract_id() -> EntityId {
        EntityId::new()
    }

    #[test]
    fn json_removed_field() {
        let old = r#"{"name": "string", "email": "string", "age": 0}"#;
        let new = r#"{"name": "string", "age": 0}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::EventSchema, test_contract_id());
        assert!(!breakages.is_empty());
        assert!(breakages
            .iter()
            .any(|b| b.kind == BreakageKind::RemovedField && b.description.contains("email")));
    }

    #[test]
    fn json_type_changed() {
        let old = r#"{"count": 42}"#;
        let new = r#"{"count": "forty-two"}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::EventSchema, test_contract_id());
        assert!(breakages
            .iter()
            .any(|b| b.kind == BreakageKind::TypeChanged));
    }

    #[test]
    fn json_required_field_added() {
        let old = r#"{"required": ["name"], "properties": {"name": {}, "email": {}}}"#;
        let new = r#"{"required": ["name", "email"], "properties": {"name": {}, "email": {}}}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::OpenApi, test_contract_id());
        assert!(
            breakages
                .iter()
                .any(|b| b.kind == BreakageKind::RequiredFieldAdded
                    && b.description.contains("email"))
        );
    }

    #[test]
    fn json_enum_variant_removed() {
        let old = r#"{"status": {"type": "string", "enum": ["active", "inactive", "pending"]}}"#;
        let new = r#"{"status": {"type": "string", "enum": ["active", "inactive"]}}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::EventSchema, test_contract_id());
        assert!(breakages.iter().any(
            |b| b.kind == BreakageKind::EnumVariantRemoved && b.description.contains("pending")
        ));
    }

    #[test]
    fn json_no_breaking_changes_additive() {
        let old = r#"{"name": "string"}"#;
        let new = r#"{"name": "string", "email": "string"}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::EventSchema, test_contract_id());
        assert!(breakages.is_empty(), "additive changes should not break");
    }

    #[test]
    fn json_nested_removed_field() {
        let old = r#"{"user": {"name": "string", "address": {"city": "string", "zip": "string"}}}"#;
        let new = r#"{"user": {"name": "string", "address": {"city": "string"}}}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::EventSchema, test_contract_id());
        assert!(breakages
            .iter()
            .any(|b| b.kind == BreakageKind::RemovedField && b.description.contains("zip")));
    }

    #[test]
    fn openapi_removed_endpoint_json() {
        let old = r#"{"paths": {"/users": {}, "/pets": {}}}"#;
        let new = r#"{"paths": {"/users": {}}}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::OpenApi, test_contract_id());
        assert!(breakages
            .iter()
            .any(|b| b.kind == BreakageKind::RemovedEndpoint && b.description.contains("/pets")));
    }

    #[test]
    fn protobuf_removed_message() {
        let old = "syntax = \"proto3\";\npackage test;\nmessage User {\n  string id = 1;\n}\nmessage Order {\n  string id = 1;\n}";
        let new = "syntax = \"proto3\";\npackage test;\nmessage User {\n  string id = 1;\n}";

        let breakages =
            detect_breaking_changes(old, new, ContractKind::Protobuf, test_contract_id());
        assert!(breakages.iter().any(|b| b.description.contains("Order")));
    }

    #[test]
    fn graphql_removed_type() {
        let old = "type Query { hello: String }\ntype User { id: ID! }";
        let new = "type Query { hello: String }";

        let breakages =
            detect_breaking_changes(old, new, ContractKind::GraphQL, test_contract_id());
        assert!(breakages.iter().any(|b| b.description.contains("User")));
    }

    #[test]
    fn protobuf_removed_rpc() {
        let old = "service UserService {\n  rpc GetUser(Request) returns (Response);\n  rpc DeleteUser(Request) returns (Response);\n}";
        let new = "service UserService {\n  rpc GetUser(Request) returns (Response);\n}";

        let breakages =
            detect_breaking_changes(old, new, ContractKind::Protobuf, test_contract_id());
        assert!(breakages
            .iter()
            .any(|b| b.description.contains("DeleteUser")));
    }

    #[test]
    fn empty_schemas_no_breakage() {
        let breakages =
            detect_breaking_changes("", "", ContractKind::EventSchema, test_contract_id());
        assert!(breakages.is_empty());
    }

    #[test]
    fn json_schema_type_field_changed() {
        let old = r#"{"properties": {"age": {"type": "integer"}}, "required": ["age"]}"#;
        let new = r#"{"properties": {"age": {"type": "string"}}, "required": ["age"]}"#;

        let breakages =
            detect_breaking_changes(old, new, ContractKind::EventSchema, test_contract_id());
        assert!(breakages
            .iter()
            .any(|b| b.kind == BreakageKind::TypeChanged && b.description.contains("type")));
    }
}
