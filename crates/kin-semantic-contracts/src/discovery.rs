use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

use kin_model::{Contract, ContractKind, EntityId, Hash256};

use crate::error::Result;

/// A discovered contract schema before graph insertion.
#[derive(Debug, Clone)]
pub struct DiscoveredContract {
    pub name: String,
    pub kind: ContractKind,
    pub schema_content: String,
    pub version: Option<String>,
}

/// Semantic version bump classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemverBump {
    Major,
    Minor,
    Patch,
    Unknown,
}

/// Detect version bump between old and new discovered contracts.
///
/// Compares version strings using semver-style logic.
/// Returns `None` if either contract lacks a version.
pub fn detect_version_bump(
    old: &DiscoveredContract,
    new: &DiscoveredContract,
) -> Option<SemverBump> {
    let old_ver = old.version.as_deref()?;
    let new_ver = new.version.as_deref()?;
    Some(classify_semver_bump(old_ver, new_ver))
}

/// Parse a version string into (major, minor, patch) components.
/// Handles formats like "1.2.3", "v1.2.3", "1.0", "1".
fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let v = version
        .trim()
        .trim_start_matches('v')
        .trim_start_matches('V');
    let parts: Vec<&str> = v.split('.').collect();
    let major = parts.first()?.parse::<u64>().ok()?;
    let minor = parts
        .get(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let patch = parts
        .get(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

fn classify_semver_bump(old: &str, new: &str) -> SemverBump {
    match (parse_semver(old), parse_semver(new)) {
        (Some((om, omi, op)), Some((nm, nmi, np))) => {
            if nm > om {
                SemverBump::Major
            } else if nm == om && nmi > omi {
                SemverBump::Minor
            } else if nm == om && nmi == omi && np > op {
                SemverBump::Patch
            } else if nm == om && nmi == omi && np == op {
                // Same version — treat as unknown (no bump)
                SemverBump::Unknown
            } else {
                // Downgrade or unusual change
                SemverBump::Unknown
            }
        }
        _ => SemverBump::Unknown,
    }
}

impl DiscoveredContract {
    /// Convert to a model Contract with a content-addressed schema hash.
    pub fn into_contract(self) -> Contract {
        let schema_hash = hash_schema(&self.schema_content);
        Contract {
            id: EntityId::new(),
            kind: self.kind,
            name: self.name,
            schema_hash,
            producers: Vec::new(),
            consumers: Vec::new(),
            version: self.version,
        }
    }
}

/// Detect contract kind from file path and content.
pub fn detect_contract(path: &str, content: &str) -> Result<Option<DiscoveredContract>> {
    // OpenAPI detection
    if is_openapi(path, content) {
        let name = extract_openapi_title(content).unwrap_or_else(|| path.to_string());
        let version = extract_openapi_version(content);
        debug!(path, name = %name, "discovered OpenAPI contract");
        return Ok(Some(DiscoveredContract {
            name,
            kind: ContractKind::OpenApi,
            schema_content: content.to_string(),
            version,
        }));
    }

    // Protobuf detection
    if path.ends_with(".proto") {
        let name = extract_proto_package(content).unwrap_or_else(|| path.to_string());
        let version = extract_proto_version(content);
        debug!(path, name = %name, "discovered Protobuf contract");
        return Ok(Some(DiscoveredContract {
            name,
            kind: ContractKind::Protobuf,
            schema_content: content.to_string(),
            version,
        }));
    }

    // GraphQL schema detection
    if path.ends_with(".graphql") || path.ends_with(".gql") {
        let name = extract_graphql_name(path);
        let version = extract_graphql_version(content);
        debug!(path, name = %name, "discovered GraphQL contract");
        return Ok(Some(DiscoveredContract {
            name,
            kind: ContractKind::GraphQL,
            schema_content: content.to_string(),
            version,
        }));
    }

    // DB schema / migration detection
    if path.ends_with(".sql")
        && (path.contains("migration") || path.contains("schema") || path.contains("migrate"))
    {
        let name = extract_sql_name(path);
        debug!(path, name = %name, "discovered DB schema contract");
        return Ok(Some(DiscoveredContract {
            name,
            kind: ContractKind::DbSchema,
            schema_content: content.to_string(),
            version: None,
        }));
    }

    // Event schema detection (JSON Schema with event-like structure)
    if is_event_schema(path, content) {
        let name = extract_json_title(content).unwrap_or_else(|| path.to_string());
        debug!(path, name = %name, "discovered event schema contract");
        return Ok(Some(DiscoveredContract {
            name,
            kind: ContractKind::EventSchema,
            schema_content: content.to_string(),
            version: None,
        }));
    }

    Ok(None)
}

fn is_openapi(path: &str, content: &str) -> bool {
    if path.ends_with(".yaml") || path.ends_with(".yml") || path.ends_with(".json") {
        content.contains("openapi") || content.contains("swagger")
    } else {
        false
    }
}

fn extract_openapi_title(content: &str) -> Option<String> {
    // Simple heuristic: look for "title:" or "\"title\":" in the content
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("title:") {
            return Some(
                trimmed
                    .trim_start_matches("title:")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            );
        }
        if trimmed.contains("\"title\"") {
            if let Some(val) = trimmed.split(':').nth(1) {
                return Some(
                    val.trim()
                        .trim_matches(',')
                        .trim_matches('"')
                        .trim()
                        .to_string(),
                );
            }
        }
    }
    None
}

fn extract_openapi_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version:") {
            return Some(
                trimmed
                    .trim_start_matches("version:")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            );
        }
    }
    None
}

fn extract_proto_package(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("package ") {
            return Some(
                trimmed
                    .trim_start_matches("package ")
                    .trim_end_matches(';')
                    .trim()
                    .to_string(),
            );
        }
    }
    None
}

fn extract_graphql_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("schema")
        .to_string()
}

fn extract_sql_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("migration")
        .to_string()
}

/// Extract version from protobuf syntax declaration and optional version comments.
/// Falls back to the proto syntax version (e.g., "proto3" -> "3").
fn extract_proto_version(content: &str) -> Option<String> {
    // First, look for explicit version comments like `// version: 1.2.0`
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            let comment = trimmed.trim_start_matches("//").trim();
            if let Some(ver) = comment.strip_prefix("version:") {
                let ver = ver.trim();
                if !ver.is_empty() {
                    return Some(ver.to_string());
                }
            }
        }
    }
    // Fall back to syntax version as a hint
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("syntax") {
            // syntax = "proto3"; -> "3"
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    let syntax = &trimmed[start + 1..start + 1 + end];
                    let version = syntax.trim_start_matches("proto");
                    if !version.is_empty() {
                        return Some(version.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract version from GraphQL schema directives.
/// Looks for `@version(number: "X.Y.Z")` or `# version: X.Y.Z` comments.
fn extract_graphql_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        // Directive style: @version(number: "1.0.0")
        if let Some(idx) = trimmed.find("@version") {
            let rest = &trimmed[idx..];
            if let Some(start) = rest.find('"') {
                if let Some(end) = rest[start + 1..].find('"') {
                    return Some(rest[start + 1..start + 1 + end].to_string());
                }
            }
        }
        // Comment style: # version: 1.0.0
        if trimmed.starts_with('#') {
            let comment = trimmed.trim_start_matches('#').trim();
            if let Some(ver) = comment.strip_prefix("version:") {
                let ver = ver.trim();
                if !ver.is_empty() {
                    return Some(ver.to_string());
                }
            }
        }
    }
    None
}

fn is_event_schema(path: &str, content: &str) -> bool {
    if !path.ends_with(".json") {
        return false;
    }
    // Heuristic: contains "$schema" and "event" or "message" in name/path
    content.contains("$schema")
        && (path.contains("event") || path.contains("message") || content.contains("\"event\""))
}

fn extract_json_title(content: &str) -> Option<String> {
    // Try to parse as JSON and find "title" field
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    value
        .get("title")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn hash_schema(content: &str) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_openapi_yaml() {
        let content = r#"
openapi: "3.0.0"
info:
  title: Pet Store API
  version: 1.0.0
paths: {}
"#;
        let result = detect_contract("api.yaml", content).unwrap();
        assert!(result.is_some());
        let contract = result.unwrap();
        assert_eq!(contract.kind, ContractKind::OpenApi);
        assert_eq!(contract.name, "Pet Store API");
        assert_eq!(contract.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn detect_protobuf() {
        let content = r#"
syntax = "proto3";
package myapp.users;

message User {
    string id = 1;
    string name = 2;
}
"#;
        let result = detect_contract("user.proto", content).unwrap();
        assert!(result.is_some());
        let contract = result.unwrap();
        assert_eq!(contract.kind, ContractKind::Protobuf);
        assert_eq!(contract.name, "myapp.users");
    }

    #[test]
    fn detect_graphql() {
        let content = "type Query { hello: String }";
        let result = detect_contract("schema.graphql", content).unwrap();
        assert!(result.is_some());
        let contract = result.unwrap();
        assert_eq!(contract.kind, ContractKind::GraphQL);
        assert_eq!(contract.name, "schema");
    }

    #[test]
    fn detect_sql_migration() {
        let content = "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255));";
        let result = detect_contract("migrations/001_create_users.sql", content).unwrap();
        assert!(result.is_some());
        let contract = result.unwrap();
        assert_eq!(contract.kind, ContractKind::DbSchema);
    }

    #[test]
    fn detect_event_schema() {
        let content = r#"{"$schema": "http://json-schema.org/draft-07/schema#", "title": "UserCreated", "type": "object"}"#;
        let result = detect_contract("events/user_created.json", content).unwrap();
        assert!(result.is_some());
        let contract = result.unwrap();
        assert_eq!(contract.kind, ContractKind::EventSchema);
        assert_eq!(contract.name, "UserCreated");
    }

    #[test]
    fn detect_protobuf_with_syntax_version() {
        let content = "syntax = \"proto3\";\npackage myapp.users;\nmessage User { string id = 1; }";
        let result = detect_contract("user.proto", content).unwrap().unwrap();
        assert_eq!(result.version.as_deref(), Some("3"));
    }

    #[test]
    fn detect_protobuf_with_explicit_version_comment() {
        let content = "// version: 2.1.0\nsyntax = \"proto3\";\npackage myapp;\nmessage Msg { }";
        let result = detect_contract("msg.proto", content).unwrap().unwrap();
        assert_eq!(result.version.as_deref(), Some("2.1.0"));
    }

    #[test]
    fn detect_graphql_with_version_directive() {
        let content = "type Query @version(number: \"1.5.0\") { hello: String }";
        let result = detect_contract("schema.graphql", content).unwrap().unwrap();
        assert_eq!(result.version.as_deref(), Some("1.5.0"));
    }

    #[test]
    fn detect_graphql_with_version_comment() {
        let content = "# version: 3.0.0\ntype Query { hello: String }";
        let result = detect_contract("api.gql", content).unwrap().unwrap();
        assert_eq!(result.version.as_deref(), Some("3.0.0"));
    }

    #[test]
    fn semver_bump_major() {
        let old = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.2.3".into()),
        };
        let new = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("2.0.0".into()),
        };
        assert_eq!(detect_version_bump(&old, &new), Some(SemverBump::Major));
    }

    #[test]
    fn semver_bump_minor() {
        let old = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.2.3".into()),
        };
        let new = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.3.0".into()),
        };
        assert_eq!(detect_version_bump(&old, &new), Some(SemverBump::Minor));
    }

    #[test]
    fn semver_bump_patch() {
        let old = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.2.3".into()),
        };
        let new = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.2.4".into()),
        };
        assert_eq!(detect_version_bump(&old, &new), Some(SemverBump::Patch));
    }

    #[test]
    fn semver_bump_none_returns_none() {
        let old = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: None,
        };
        let new = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.0.0".into()),
        };
        assert_eq!(detect_version_bump(&old, &new), None);
    }

    #[test]
    fn semver_bump_v_prefix() {
        let old = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("v1.0.0".into()),
        };
        let new = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("v2.0.0".into()),
        };
        assert_eq!(detect_version_bump(&old, &new), Some(SemverBump::Major));
    }

    #[test]
    fn semver_bump_partial_versions() {
        let old = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.0".into()),
        };
        let new = DiscoveredContract {
            name: "API".into(),
            kind: ContractKind::OpenApi,
            schema_content: String::new(),
            version: Some("1.1".into()),
        };
        assert_eq!(detect_version_bump(&old, &new), Some(SemverBump::Minor));
    }

    #[test]
    fn non_contract_file_returns_none() {
        let result = detect_contract("main.rs", "fn main() {}").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn discovered_contract_to_model() {
        let discovered = DiscoveredContract {
            name: "TestAPI".to_string(),
            kind: ContractKind::OpenApi,
            schema_content: "openapi: 3.0.0".to_string(),
            version: Some("1.0".to_string()),
        };
        let contract = discovered.into_contract();
        assert_eq!(contract.name, "TestAPI");
        assert_eq!(contract.kind, ContractKind::OpenApi);
        assert_eq!(contract.version.as_deref(), Some("1.0"));
        assert!(contract.producers.is_empty());
        assert!(contract.consumers.is_empty());
    }
}
