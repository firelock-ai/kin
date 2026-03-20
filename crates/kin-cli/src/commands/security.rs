// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{EntityKind, GraphStore, Relation, RelationKind, Visibility};

/// Security finding from the entity graph scan.
#[derive(Debug)]
struct SecurityFinding {
    severity: Severity,
    category: &'static str,
    message: String,
    entity_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
        }
    }
}

/// Scan the entity graph for known vulnerability patterns.
///
/// `kin security` analyzes the semantic graph locally for:
///   - Exposed API endpoints without tests
///   - Public entities with no callers (orphaned surface area)
///   - Deep dependency chains (transitive risk)
///   - Event contracts without consumers (dead events)
///   - Public entities calling private internals (encapsulation leaks)
///
/// When `--propagate` is set, additionally traces transitive dependency
/// chains for each finding to surface downstream vulnerability propagation.
pub async fn run_with_options(propagate: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let entities = graph.list_all_entities()?;

    if entities.is_empty() {
        println!("No entities in graph. Run `kin commit` first.");
        return Ok(());
    }

    let mut findings: Vec<SecurityFinding> = Vec::new();

    // Check each entity for patterns
    for entity in &entities {
        let relations = graph.get_all_relations_for_entity(&entity.id)?;

        // 1. Exposed API endpoints without test coverage
        if entity.kind == EntityKind::ApiEndpoint {
            let has_test = relations.iter().any(|r| r.kind == RelationKind::Tests);
            if !has_test {
                findings.push(SecurityFinding {
                    severity: Severity::High,
                    category: "untested-api",
                    message: "API endpoint has no test coverage".into(),
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 2. Public functions/methods with no callers (orphaned surface area)
        if entity.visibility == Visibility::Public
            && matches!(entity.kind, EntityKind::Function | EntityKind::Method)
        {
            let has_callers = relations
                .iter()
                .any(|r| r.kind == RelationKind::Calls && r.dst == entity.id);
            let has_tests = relations.iter().any(|r| r.kind == RelationKind::Tests);
            if !has_callers && !has_tests {
                findings.push(SecurityFinding {
                    severity: Severity::Low,
                    category: "orphaned-public",
                    message: "Public entity has no callers or tests — unnecessary attack surface"
                        .into(),
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 3. Deep dependency chains (transitive risk)
        if entity.visibility == Visibility::Public {
            let downstream = graph.get_downstream_impact(&entity.id, 5)?;
            if downstream.len() > 20 {
                findings.push(SecurityFinding {
                    severity: Severity::Medium,
                    category: "high-fan-out",
                    message: format!(
                        "Public entity has {} downstream dependents (high blast radius)",
                        downstream.len()
                    ),
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 4. Event contracts without consumers
        if entity.kind == EntityKind::EventContract {
            let has_consumer = relations
                .iter()
                .any(|r| r.kind == RelationKind::ConsumesContract && r.src != entity.id);
            if !has_consumer {
                findings.push(SecurityFinding {
                    severity: Severity::Medium,
                    category: "dead-event",
                    message:
                        "Event contract has no consumers — potential dead code or missing handler"
                            .into(),
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 5. Public entity calling private internals (encapsulation leak)
        if entity.visibility == Visibility::Public {
            let outgoing_calls: Vec<&Relation> = relations
                .iter()
                .filter(|r| r.kind == RelationKind::Calls && r.src == entity.id)
                .collect();
            for call in outgoing_calls {
                if let Some(target) = graph.get_entity(&call.dst)? {
                    if target.visibility == Visibility::Private {
                        findings.push(SecurityFinding {
                            severity: Severity::Low,
                            category: "encapsulation-leak",
                            message: format!(
                                "Public entity calls private '{}' — encapsulation boundary violation",
                                target.name
                            ),
                            entity_name: entity.name.clone(),
                        });
                    }
                }
            }
        }
    }

    // 6. Transitive vulnerability propagation (--propagate)
    if propagate {
        let finding_entity_names: Vec<String> =
            findings.iter().map(|f| f.entity_name.clone()).collect();
        let mut transitive_findings = Vec::new();

        for entity in &entities {
            if !finding_entity_names.contains(&entity.name) {
                continue;
            }
            let downstream = graph.get_downstream_impact(&entity.id, 10)?;
            for dep in &downstream {
                transitive_findings.push(SecurityFinding {
                    severity: Severity::Info,
                    category: "transitive-dependency",
                    message: format!(
                        "Transitively affected by vulnerable '{}' (depth <= 10)",
                        entity.name
                    ),
                    entity_name: dep.name.clone(),
                });
            }
        }

        findings.extend(transitive_findings);
    }

    // Sort by severity (highest first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Print results
    println!("Security scan: {} entities analyzed", entities.len());
    if propagate {
        println!("  (transitive propagation enabled)");
    }
    println!();

    if findings.is_empty() {
        println!("  No security findings detected.");
        return Ok(());
    }

    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    println!(
        "  Findings: {} total ({} high, {} medium, {} low, {} info)",
        findings.len(),
        high_count,
        medium_count,
        low_count,
        info_count
    );
    println!();

    for finding in &findings {
        println!(
            "  [{}] {} ({})",
            finding.severity, finding.entity_name, finding.category
        );
        println!("    {}", finding.message);
    }

    if high_count > 0 {
        println!();
        println!(
            "  {} high-severity finding(s) require attention.",
            high_count
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", Severity::High), "HIGH");
        assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
        assert_eq!(format!("{}", Severity::Low), "LOW");
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }

    #[test]
    fn finding_struct() {
        let finding = SecurityFinding {
            severity: Severity::High,
            category: "untested-api",
            message: "API endpoint has no tests".into(),
            entity_name: "handleLogin".into(),
        };
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.entity_name, "handleLogin");
    }
}
