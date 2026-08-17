// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, RelationKind, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, FileImport, ImportedName, ParseOutput};

pub struct HclAdapter;

impl LanguageAdapter for HclAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Hcl
    }

    fn file_extensions(&self) -> &[&str] {
        &["tf", "tfvars"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_hcl::LANGUAGE)?;
        parser
            .parse(source, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            })
    }

    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput> {
        let error_ranges = collect_error_ranges(tree);
        let parse_state = if error_ranges.is_empty() {
            ParseState::Valid
        } else {
            ParseState::Incomplete { error_ranges }
        };

        let mut entities = Vec::new();
        let mut relations = Vec::new();
        let mut imports = Vec::new();
        let root = tree.root_node();

        // The tree-sitter-hcl grammar wraps everything in: config_file -> body -> block/attribute
        // We need to iterate over the children of the top-level `body` node.
        let body = find_child_by_kind(&root, "body").unwrap_or(root);
        let mut cursor = body.walk();

        for child in body.children(&mut cursor) {
            if child.kind() == "block" {
                extract_hcl_block(
                    &child,
                    source,
                    file_id,
                    &mut entities,
                    &mut relations,
                    &mut imports,
                );
            } else if child.kind() == "attribute" {
                // Top-level attributes (e.g., terraform settings)
                extract_hcl_top_attribute(&child, source, file_id, &mut entities);
            }
        }

        // Scan for cross-resource references in attribute values.
        // Patterns like `aws_instance.web.id` or `var.region` or `module.vpc.output`.
        for entity in &entities {
            extract_references_from_span(&root, source, &entity.name, &entity.span, &mut relations);
        }

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests: Vec::new(),
            parse_state,
        })
    }
}

/// Extract entities from a top-level HCL block.
///
/// HCL blocks have the form:
///   block_type "label1" "label2" { body }
///
/// For Terraform, the block types we care about:
///   resource "type" "name" { ... }
///   data "type" "name" { ... }
///   variable "name" { ... }
///   output "name" { ... }
///   locals { ... }
///   module "name" { ... }
///   provider "name" { ... }
///   terraform { ... }
fn extract_hcl_block(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    imports: &mut Vec<FileImport>,
) {
    let mut block_cursor = node.walk();
    let children: Vec<_> = node.children(&mut block_cursor).collect();

    // First named child is the block type identifier
    let block_type = children
        .iter()
        .find(|c| c.kind() == "identifier")
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("");

    // Collect string labels (strip quotes)
    let labels: Vec<String> = children
        .iter()
        .filter(|c| c.kind() == "string_lit")
        .filter_map(|n| {
            let text = n.utf8_text(source).ok()?;
            Some(strip_quotes(text))
        })
        .collect();

    match block_type {
        "resource" => {
            // resource "aws_instance" "web" { ... }
            if labels.len() >= 2 {
                let resource_type = &labels[0];
                let resource_name = &labels[1];
                let qualified = format!("{}.{}", resource_type, resource_name);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Schema,
                    name: qualified,
                    signature: format!("resource \"{}\" \"{}\"", resource_type, resource_name),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "data" => {
            // data "aws_ami" "ubuntu" { ... }
            if labels.len() >= 2 {
                let data_type = &labels[0];
                let data_name = &labels[1];
                let qualified = format!("data.{}.{}", data_type, data_name);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Schema,
                    name: qualified,
                    signature: format!("data \"{}\" \"{}\"", data_type, data_name),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "variable" => {
            // variable "region" { ... }
            if let Some(var_name) = labels.first() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::StaticVar,
                    name: format!("var.{}", var_name),
                    signature: format!("variable \"{}\"", var_name),
                    visibility: Visibility::Public,
                    doc_summary: extract_description_attr(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "output" => {
            // output "instance_ip" { ... }
            if let Some(out_name) = labels.first() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::StaticVar,
                    name: format!("output.{}", out_name),
                    signature: format!("output \"{}\"", out_name),
                    visibility: Visibility::Public,
                    doc_summary: extract_description_attr(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "module" => {
            // module "vpc" { source = "./modules/vpc" ... }
            if let Some(mod_name) = labels.first() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Module,
                    name: format!("module.{}", mod_name),
                    signature: format!("module \"{}\"", mod_name),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Extract source attribute as an import
                if let Some(source_val) = extract_block_attr(node, source, "source") {
                    imports.push(FileImport {
                        module_path: source_val.clone(),
                        specifiers: vec![ImportedName {
                            local_name: mod_name.clone(),
                            original_name: None,
                            is_default: false,
                        }],
                    });
                    relations.push(ExtractedRelation {
                        receiver: None,
                        call_shape: None,
                        kind: RelationKind::Imports,
                        src_name: format!("module.{}", mod_name),
                        dst_name: source_val,
                        import_source: None,
                    });
                }
            }
        }
        "locals" => {
            // locals { name = value ... }
            extract_locals_block(node, source, file_id, entities);
        }
        "provider" => {
            // provider "aws" { ... }
            if let Some(provider_name) = labels.first() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Module,
                    name: format!("provider.{}", provider_name),
                    signature: format!("provider \"{}\"", provider_name),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "terraform" => {
            // terraform { required_providers { ... } }
            // Extract required_providers as references
            extract_terraform_block(node, source, relations);
        }
        _ => {}
    }
}

/// Extract local value bindings from a `locals` block.
fn extract_locals_block(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
) {
    let body = find_child_by_kind(node, "body");
    let body = match body {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "attribute" {
            if let Some(name_node) = find_child_by_kind(&child, "identifier") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Constant,
                        name: format!("local.{}", name),
                        signature: format!("local.{}", name),
                        visibility: Visibility::Internal,
                        doc_summary: extract_preceding_comment(&child, source),
                        fingerprint: compute_fingerprint(&child, source),
                        span: span_from_node(&child, file_id),
                    });
                }
            }
        }
    }
}

/// Extract required_providers from a terraform block as relations.
fn extract_terraform_block(
    node: &tree_sitter::Node,
    source: &[u8],
    relations: &mut Vec<ExtractedRelation>,
) {
    let body = match find_child_by_kind(node, "body") {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "block" {
            let block_type = find_child_by_kind(&child, "identifier")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            if block_type == "required_providers" {
                extract_required_providers(&child, source, relations);
            }
        }
    }
}

/// Extract provider references from a required_providers block.
fn extract_required_providers(
    node: &tree_sitter::Node,
    source: &[u8],
    relations: &mut Vec<ExtractedRelation>,
) {
    let body = match find_child_by_kind(node, "body") {
        Some(b) => b,
        None => return,
    };
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "attribute" {
            if let Some(name_node) = find_child_by_kind(&child, "identifier") {
                let provider_name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !provider_name.is_empty() {
                    // Extract source from the object value if present
                    let source_val = extract_object_attr(&child, source, "source")
                        .unwrap_or_else(|| format!("hashicorp/{}", provider_name));
                    relations.push(ExtractedRelation {
                        receiver: None,
                        call_shape: None,
                        kind: RelationKind::References,
                        src_name: "terraform".to_string(),
                        dst_name: source_val,
                        import_source: None,
                    });
                }
            }
        }
    }
}

/// Extract a top-level attribute (outside any block).
fn extract_hcl_top_attribute(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
) {
    if let Some(name_node) = find_child_by_kind(node, "identifier") {
        let name = name_node.utf8_text(source).unwrap_or("").to_string();
        if !name.is_empty() {
            entities.push(ExtractedEntity {
                kind: EntityKind::Constant,
                name,
                signature: node_signature(node, source),
                visibility: Visibility::Internal,
                doc_summary: extract_preceding_comment(node, source),
                fingerprint: compute_fingerprint(node, source),
                span: span_from_node(node, file_id),
            });
        }
    }
}

/// Scan entity bodies for cross-resource references.
///
/// Terraform references follow patterns like:
///   aws_instance.web.id    (resource reference)
///   var.region             (variable reference)
///   module.vpc.subnet_id   (module output reference)
///   data.aws_ami.ubuntu.id (data source reference)
///   local.common_tags      (local value reference)
fn extract_references_from_span(
    root: &tree_sitter::Node,
    source: &[u8],
    _entity_name: &str,
    _span: &kin_model::SourceSpan,
    _relations: &mut Vec<ExtractedRelation>,
) {
    // Walk the entire tree looking for variable_expr nodes that indicate
    // cross-resource references. The tree-sitter-hcl grammar represents
    // these as get_attr chains on identifiers.
    //
    // For the initial implementation we extract relations at the block level
    // during extract_hcl_block (module source, required_providers). More
    // granular reference tracking (e.g. interpolation expressions) can be
    // added as a follow-up once we validate the grammar node types in practice.
    let _ = (root, source);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn strip_quotes(s: &str) -> String {
    s.trim_matches('"').to_string()
}

fn find_child_by_kind<'a>(
    node: &'a tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    let result = node.children(&mut cursor).find(|c| c.kind() == kind);
    result
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "comment" {
        let text = prev.utf8_text(source).ok()?;
        let cleaned = text
            .trim_start_matches('#')
            .trim_start_matches('/')
            .trim()
            .to_string();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    } else {
        None
    }
}

/// Extract the `description` attribute value from inside a block body.
/// Falls back to preceding comment if no description attribute exists.
fn extract_description_attr(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if let Some(val) = extract_block_attr(node, source, "description") {
        return Some(val);
    }
    extract_preceding_comment(node, source)
}

/// Extract a string attribute value from a block body.
fn extract_block_attr(node: &tree_sitter::Node, source: &[u8], attr_name: &str) -> Option<String> {
    let body = find_child_by_kind(node, "body")?;
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "attribute" {
            let name =
                find_child_by_kind(&child, "identifier").and_then(|n| n.utf8_text(source).ok())?;
            if name == attr_name {
                // Value is nested: attribute -> expression -> literal_value -> string_lit
                if let Some(text) = find_string_lit_recursive(&child, source) {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Recursively find the first string_lit in a subtree and return its unquoted text.
fn find_string_lit_recursive(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() == "string_lit"
        || node.kind() == "template_expr"
        || node.kind() == "quoted_template"
    {
        let text = node.utf8_text(source).unwrap_or("");
        return Some(strip_quotes(text));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(val) = find_string_lit_recursive(&child, source) {
            return Some(val);
        }
    }
    None
}

/// Extract a string value from an object attribute (e.g., `source` inside `{ source = "..." }`).
fn extract_object_attr(node: &tree_sitter::Node, source: &[u8], attr_name: &str) -> Option<String> {
    // Find object_elem nodes anywhere in the subtree, then check their key identifier.
    // Structure: attribute -> expression -> collection_value -> object -> object_elem
    // object_elem has key: expression(variable_expr(identifier)) and val: expression(...)
    find_object_attr_recursive(node, source, attr_name)
}

fn find_object_attr_recursive(
    node: &tree_sitter::Node,
    source: &[u8],
    attr_name: &str,
) -> Option<String> {
    if node.kind() == "object_elem" {
        // object_elem structure: key: expression(variable_expr(identifier)) val: expression(...)
        // Use named children: "key" and "val" fields, or fall back to expression children.
        let mut cursor = node.walk();
        let exprs: Vec<_> = node
            .children(&mut cursor)
            .filter(|c| c.kind() == "expression")
            .collect();
        if exprs.len() >= 2 {
            // Check if the key expression contains an identifier matching attr_name
            if let Some(key_id) = find_first_identifier(&exprs[0], source) {
                if key_id == attr_name {
                    return find_string_lit_recursive(&exprs[1], source);
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(val) = find_object_attr_recursive(&child, source, attr_name) {
            return Some(val);
        }
    }
    None
}

/// Find the first identifier text in a subtree.
fn find_first_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return node.utf8_text(source).ok().map(|s| s.to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(id) = find_first_identifier(&child, source) {
            return Some(id);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resource_block() {
        let adapter = HclAdapter;
        let source = br#"
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let resources: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Schema)
            .collect();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name, "aws_instance.web");
        assert_eq!(resources[0].signature, "resource \"aws_instance\" \"web\"");
    }

    #[test]
    fn parse_data_source() {
        let adapter = HclAdapter;
        let source = br#"
data "aws_ami" "ubuntu" {
  most_recent = true
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("data.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let data_sources: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("data."))
            .collect();
        assert_eq!(data_sources.len(), 1);
        assert_eq!(data_sources[0].name, "data.aws_ami.ubuntu");
    }

    #[test]
    fn parse_variable() {
        let adapter = HclAdapter;
        let source = br#"
variable "region" {
  description = "AWS region"
  default     = "us-west-2"
  type        = string
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("variables.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let vars: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::StaticVar)
            .collect();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, "var.region");
    }

    #[test]
    fn parse_output() {
        let adapter = HclAdapter;
        let source = br#"
output "instance_ip" {
  description = "The public IP"
  value       = aws_instance.web.public_ip
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("outputs.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let outputs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("output."))
            .collect();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].name, "output.instance_ip");
    }

    #[test]
    fn parse_module_with_source() {
        let adapter = HclAdapter;
        let source = br#"
module "vpc" {
  source = "./modules/vpc"
  cidr   = "10.0.0.0/16"
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "module.vpc");

        // Module source should create an import
        assert_eq!(output.imports.len(), 1);
        assert_eq!(output.imports[0].module_path, "./modules/vpc");
        assert_eq!(output.imports[0].specifiers[0].local_name, "vpc");

        // And an Imports relation
        let import_rels: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == RelationKind::Imports)
            .collect();
        assert_eq!(import_rels.len(), 1);
        assert_eq!(import_rels[0].src_name, "module.vpc");
        assert_eq!(import_rels[0].dst_name, "./modules/vpc");
    }

    #[test]
    fn parse_locals() {
        let adapter = HclAdapter;
        let source = br#"
locals {
  common_tags = {
    Project = "kin"
  }
  env = "production"
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("locals.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let locals: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(locals.len(), 2);
        let names: Vec<&str> = locals.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"local.common_tags"));
        assert!(names.contains(&"local.env"));
    }

    #[test]
    fn parse_provider() {
        let adapter = HclAdapter;
        let source = br#"
provider "aws" {
  region = "us-west-2"
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("provider.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let providers: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("provider."))
            .collect();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "provider.aws");
    }

    #[test]
    fn parse_multiple_resources() {
        let adapter = HclAdapter;
        let source = br#"
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

variable "env" {
  default = "dev"
}

output "vpc_id" {
  value = aws_vpc.main.id
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("infra.tf");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(
            output
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Schema)
                .count(),
            2
        );
        assert_eq!(
            output
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::StaticVar)
                .count(),
            2 // var.env + output.vpc_id
        );
    }

    #[test]
    fn file_extensions_include_tf_and_tfvars() {
        let adapter = HclAdapter;
        let exts = adapter.file_extensions();
        assert!(exts.contains(&"tf"));
        assert!(exts.contains(&"tfvars"));
    }
}
