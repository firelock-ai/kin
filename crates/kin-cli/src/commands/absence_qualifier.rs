//! Say, in a human sentence, that an empty answer is not evidence of absence.
//!
//! One implementation for every CLI surface that answers an absence question,
//! because the defect this module exists to close is two surfaces answering the
//! same question differently (FIR-2492, FIR-2524). A second copy per command
//! would be that defect arriving by the door the fix left open.
//!
//! The VERDICT is never computed here. [`kin_mcp::negative::negative_for`] is
//! the one gate, called with the tool name whose declaration matches what the
//! command actually reads, so a CLI surface cannot reach a different conclusion
//! from its MCP counterpart about one store. Only the RENDERING is local,
//! because a person reading a terminal is not parsing an envelope (captain's
//! ruling, 2026-08-20).
//!
//! The tool name is load-bearing rather than decorative, and it is chosen to
//! match the CLAIM the command makes rather than the code that built the answer.
//! `kin impact` declares `impact_analysis`, whose absence is inbound. `kin trace`
//! declares `trace_data_flow`, because every group a context pack carries runs
//! OUTWARD from the focal; declaring `get_context_pack` instead would reach a
//! gate whose field is `dependents`, a direction a `ContextPack` holds no group
//! for at all. `kin search` declares `semantic_search`, which reads no edge class
//! and is gated on the language scope instead. Naming the wrong one gates a
//! command on a declaration describing evidence it never gathered, which is the
//! failure `IMPACT_REFERENCE_KINDS` already warns about one level down.
//!
//! Two things then vary by tool and nothing else does: the noun the absence is
//! OF ([`absence_subject`]) and the direction an absent edge class hides
//! ([`absence_direction`]). Sharing one sentence across surfaces is how a shared
//! renderer drifts, since the verdict stays right while the claim in front of
//! the reader turns into a different one.
//!
//! Silence is the certified case. A graph whose enrichment delivered says
//! nothing extra, which is the control that stops this degrading into stamping
//! every empty result uncertain, the FIR-2404 failure wearing its opposite
//! costume.
//!
//! The line promises no remedy, and that is decided rather than inherited. On a
//! store whose sweep produced nothing the honest answer to "what should I do"
//! does not exist yet; it is FIR-2519's to create. A promised remedy that may be
//! false is the `absence_consequence` failure `kin_mcp::negative` already
//! refuses on the MCP side, and `kin init` ships one today that misattributes a
//! disabled sweep to a missing server (FIR-2531). One of those is enough.

/// The marker every line of the qualifier block carries.
///
/// The block is one line per reason the verdict refused, each beginning with
/// this phrase and the noun the absence is of, so "the answer minus its
/// qualifiers" is a structural cut rather than a phrase match. The first time
/// a second reason was rendered beside the first, a clarifying sentence went
/// out without the phrase, and a test counting the answer's own lines counted
/// it as the answer (FIR-2672).
pub const QUALIFIER_MARK: &str = "Kin cannot rule out";

/// `text` with the qualifier block removed: every line carrying
/// [`QUALIFIER_MARK`], wherever it sits.
pub fn without_qualifiers(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| !line.contains(QUALIFIER_MARK))
        .collect()
}

/// Render the qualifier for `tool`'s empty answer, or nothing when the verdict
/// certifies.
///
/// `payload` must carry the observation that tool's gate reads, which differs by
/// tool: the cross-file `edge_coverage` for the reference readers, the absence
/// scope for the language-scoped ones. Handing over a payload without one is not
/// a smaller call, it is a claim the gate refuses by construction, and the gate
/// says so rather than certifying on no evidence.
pub fn qualify(
    tool: &str,
    payload: &serde_json::Value,
    envelope: &kin_mcp::Envelope,
    indent: &str,
) -> Vec<String> {
    let response_gaps = kin_mcp::verdict::Verdict::pre_negative_gaps(payload);
    let Some(negative) = kin_mcp::negative::negative_for(tool, payload, envelope, &response_gaps)
    else {
        return Vec::new();
    };
    if negative
        .get("safe_to_conclude_absent")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Vec::new();
    }

    let observed = payload.get(kin_mcp::EDGE_COVERAGE_KEY);
    let language = observed
        .and_then(|coverage| coverage.get("language"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("this language");
    let classes = observed.and_then(|coverage| coverage.get("classes"));
    let state_of = |class: &str| -> Option<&str> {
        classes
            .and_then(|classes| classes.get(class))
            .and_then(serde_json::Value::as_str)
    };

    // Only the classes the gate rested on may be named, read off the record the
    // verdict publishes rather than recomputed, so this renderer cannot name a
    // class the decision did not use. Every requested class decides now
    // (FIR-2672), and a class the build could not produce reads `unproduced`
    // rather than `absent`, so the sentence below can say which it was.
    let decided = decided_by(tool, payload, envelope);
    // `unproduced` carries two reasons and only one of them is about the
    // linker, so they render as different sentences. A class this build mints
    // for no language at all has no resolved site to blame, and saying the
    // source carries sites the linker resolved would be a claim about code this
    // observation never made.
    let build_gap = |class: &str| -> bool {
        observed
            .and_then(|coverage| coverage.get("unproduced_evidence"))
            .and_then(|evidence| evidence.get(class))
            .and_then(|evidence| evidence.get("this_build_mints_no_entity_level_edge_for"))
            .is_some()
    };
    let unminted: Vec<&'static str> = decided
        .iter()
        .filter(|class| state_of(class) == Some("unproduced") && build_gap(class))
        .map(|class| edge_class_noun(class))
        .collect();
    let unproduced: Vec<&'static str> = decided
        .iter()
        .filter(|class| state_of(class) == Some("unproduced") && !build_gap(class))
        .map(|class| edge_class_noun(class))
        .collect();
    let missing: Vec<&'static str> = decided
        .iter()
        .filter(|class| matches!(state_of(class), Some("absent") | Some("unknown")))
        .map(|class| edge_class_noun(class))
        .collect();
    let present: Vec<&'static str> = ["calls", "imports", "references"]
        .into_iter()
        .filter(|class| state_of(class) == Some("present"))
        .map(edge_class_noun)
        .collect();

    // Naming a missing class the observation did not report would be the same
    // fabrication this module exists to end, so when nothing is absent the reason
    // is whatever the verdict actually disclosed. This is also the whole of the
    // language-scoped path: `semantic_search` reads no edge class, so its
    // qualifier always renders from the disclosed signals.
    if missing.is_empty() && unproduced.is_empty() && unminted.is_empty() {
        let subject = absence_subject(tool);
        let disclosed = negative
            .get("bounding_signals")
            .and_then(serde_json::Value::as_array)
            .map(|signals| {
                signals
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|disclosed| !disclosed.is_empty());
        return match disclosed {
            Some(disclosed) => {
                let mut lines = vec![format!(
                    "{indent}{QUALIFIER_MARK} {subject}: this answer carries [{disclosed}], so it \
                     may not reflect current truth."
                )];
                // Signals describe the substrate; they must not replace the
                // verdict's more specific source, caller or binding limitation.
                for clause in negative["trust_reason"]
                    .as_str()
                    .unwrap_or_default()
                    .split("; ")
                {
                    if let Some(factor) = clause_prose(clause) {
                        lines.push(format!("{indent}{QUALIFIER_MARK} {subject}: {factor}."));
                    }
                }
                lines
            }
            // No degraded signal and no absent class, so the reason the verdict
            // refused is neither of the two things this renderer reads directly.
            // It is still ON the verdict, as the leading clause of
            // `trust_reason`, and naming it beats the generic sentence that used
            // to stand here: measured on a store whose cross-file coverage was
            // complete, `kin refs` rendered "this answer's coverage could not be
            // established" when coverage HAD been established and the real gap
            // was `cross_repo_not_configured`. A qualifier that misnames its own
            // cause sends a reader to fix the wrong end, which is the failure
            // `focal_resolution_gap` already distinguishes two ways one level
            // down.
            // An unconfigured spine, alone, is not a gap in THIS repository.
            None if only_unconfigured_federation(&negative) => return Vec::new(),
            None => vec![match limiting_factor(&negative) {
                Some(factor) => format!("{indent}{QUALIFIER_MARK} {subject}: {factor}."),
                None => format!(
                    "{indent}{QUALIFIER_MARK} {subject}: this answer's coverage could not be \
                     established."
                ),
            }],
        };
    }

    // One marked line per reason, in the order the verdict weighs them: the
    // class the build could not produce, the class the graph holds none of,
    // then the signals below. The present classes are named on the last class
    // line rather than on a line of their own, because a line without the
    // marker is not part of the block a reader or a test can cut.
    let subject = absence_subject(tool);
    let stand_in = |short: &[&str]| -> String {
        if present.is_empty() {
            String::new()
        } else {
            format!(
                " Cross-file {} edges exist but do not stand in for {} edges.",
                present.join(" and "),
                short.join(" or ")
            )
        }
    };
    let short_all: Vec<&str> = unminted
        .iter()
        .chain(unproduced.iter())
        .chain(missing.iter())
        .copied()
        .collect();
    let mut said = Vec::new();
    if !unminted.is_empty() {
        let tail = if unproduced.is_empty() && missing.is_empty() {
            stand_in(&short_all)
        } else {
            String::new()
        };
        said.push(format!(
            "{indent}{QUALIFIER_MARK} {subject}: this build mints no entity-level {} edge for \
             {language} at all, and the graph therefore holds none to find, {}. The gap is in \
             this build, not in the code.{tail}",
            unminted.join(" or "),
            absence_direction(tool)
        ));
    }
    if !unproduced.is_empty() {
        let tail = if missing.is_empty() {
            stand_in(&short_all)
        } else {
            String::new()
        };
        said.push(format!(
            "{indent}{QUALIFIER_MARK} {subject}: this build produced no entity-level {} edge for \
             {language} although the source carries {} sites, {}. The gap is in the linker, \
             not in the code.{tail}",
            unproduced.join(" or "),
            unproduced.join(" or "),
            absence_direction(tool)
        ));
    }
    if !missing.is_empty() {
        let tail = stand_in(&short_all);
        said.push(format!(
            "{indent}{QUALIFIER_MARK} {subject}: this graph holds no cross-file {} edges for \
             {language}, {}.{tail}",
            missing.join(" or "),
            absence_direction(tool)
        ));
    }
    // Independent bounding signals remain visible beside a class gap. The
    // verdict selects them, so a disclosed flag from an unrelated producer
    // cannot become the explanation for why this answer was refused.
    let independent: Vec<&str> = negative
        .get("bounding_signals")
        .and_then(serde_json::Value::as_array)
        .map(|signals| {
            signals
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|label| {
                    !label.starts_with("edge_coverage:") && !label.starts_with("absence_coverage:")
                })
                .collect()
        })
        .unwrap_or_default();
    if !independent.is_empty() {
        said.push(format!(
            "{indent}{QUALIFIER_MARK} {subject}: this answer also carries [{}], so it may not \
             reflect current truth.",
            independent.join(", ")
        ));
    }
    debug_assert!(
        said.iter().all(|line| line.contains(QUALIFIER_MARK)),
        "every qualifying line carries the marker: {said:?}"
    );
    said
}

/// Whether the ONLY thing the verdict rested on is a cross-repo spine nobody
/// configured.
///
/// A rendering decision, not a second verdict: the object `negative_for`
/// returned is still carried verbatim on the machine surface, so an agent
/// reading `--json` sees exactly what the MCP tool would say. What is withheld
/// is the SENTENCE, in this one state.
///
/// It has to be withheld, and a standing test says so. `find_references` gates
/// on `cross_repo`, and a repository with no spine reports `not_configured`,
/// which the gate counts as a gap. Without this, the qualifier fires on EVERY
/// empty `kin refs` on EVERY non-federated repository, including a healthy one
/// whose cross-file coverage is complete and whose focal is genuinely dead. That
/// is the FIR-2404 failure in its opposite costume, and FIR-2524's own negative
/// control forbids it in as many words: a genuinely dead entity on a healthy
/// enriched store must still read plainly, with no qualifier attached.
/// `genuinely_unreferenced_entity_still_gets_the_plain_empty_answer` is the
/// guard, and it caught this exact regression on the first CI run of the change
/// that introduced it.
///
/// The producing handler agrees. It emits `not_configured` under its own comment
/// "Local-only (no spine configured): cross-repo refs don't apply", so speaking
/// this gap to a person reading one local repository would repeat as a warning a
/// fact the code that published it documents as inapplicable.
///
/// Narrow on purpose: it fires only when NOTHING else is in the trust reason. An
/// unconfigured spine beside an absent edge class leaves the edge class naming
/// the sentence, and a spine that IS configured and answered badly
/// (`cross_repo_authority_incomplete`, `cross_repo_unavailable`) is a real gap
/// about a real federation and still speaks.
fn only_unconfigured_federation(negative: &serde_json::Value) -> bool {
    let Some(reason) = negative
        .get("trust_reason")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let clauses: Vec<&str> = reason
        .split("; ")
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .collect();
    !clauses.is_empty()
        && clauses
            .iter()
            .all(|clause| clause.starts_with("cross_repo_not_configured"))
}

/// The verdict's own leading reason, in the words it published.
///
/// `trust_reason` is a semicolon-joined list of every gap the gate pushed, in
/// the order it pushed them, and the gate orders them so the most specific one
/// leads. Taking the head is therefore taking the reason the refusal is most
/// ABOUT, which is the same rule the acceptance suite's check 2 already asserts
/// against this field. The trailing clause after the first colon is the
/// explanation, kept, because a bare machine token like
/// `cross_repo_not_configured` is not a sentence a person can act on.
fn limiting_factor(negative: &serde_json::Value) -> Option<String> {
    let reason = negative.get("trust_reason")?.as_str()?.trim();
    let head = reason.split("; ").next().unwrap_or(reason).trim();
    clause_prose(head)
}

/// Retain a rendered trust-reason segment's explanation. This is prose
/// presentation, not reconstruction of the verdict's machine clause codes.
fn clause_prose(clause: &str) -> Option<String> {
    let head = clause.trim();
    if head.is_empty() {
        return None;
    }
    // Drop the machine token, keep its explanation. A reason carrying no colon
    // is already prose and is used whole.
    let said = match head.split_once(": ") {
        Some((_token, prose)) if !prose.trim().is_empty() => prose.trim(),
        _ => head,
    };
    Some(said.trim_end_matches('.').to_string())
}

/// The classes the verdict says it rested on, read off the published
/// completeness block rather than recomputed.
///
/// `_kin.completeness.decided_by` is the verdict's own record of what it weighed
/// (FIR-2505), so a renderer that reads it cannot name a class the decision did
/// not use. Going through the same `finalize_with_envelope` the MCP surface goes
/// through is the point: one producer, one record, two readers.
///
/// An empty answer here names no class, which is the conservative direction: the
/// caller then falls back to the disclosed signals rather than inventing an edge
/// class nobody observed.
fn decided_by(
    tool: &str,
    payload: &serde_json::Value,
    envelope: &kin_mcp::Envelope,
) -> Vec<String> {
    let annotated = kin_mcp::finalize_with_envelope(
        kin_mcp::ToolCallResult::text(payload.to_string()),
        envelope.clone(),
        tool,
    );
    annotated
        .content
        .iter()
        .find_map(|block| match block {
            kin_mcp::ContentBlock::Text { text } => {
                serde_json::from_str::<serde_json::Value>(text).ok()
            }
        })
        .and_then(|value| {
            value
                .get(kin_mcp::ENVELOPE_KEY)
                .and_then(|envelope| envelope.get("completeness"))
                .and_then(|completeness| completeness.get("decided_by"))
                .and_then(serde_json::Value::as_array)
                .map(|classes| {
                    classes
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
        })
        .unwrap_or_default()
}

/// What this tool's empty answer is an absence OF, in the reader's own terms.
///
/// Load-bearing rather than cosmetic, and it is the one thing sharing an
/// implementation across surfaces gets wrong by default. `kin impact` and
/// `kin trace` ask which code reaches an entity, so their absence is an absence
/// of DEPENDENTS, which is the same noun the substrate's own retrieval spec uses
/// for both (`no_dependents`, "nothing was found depending on the focal
/// entity"). `kin search` asks whether the index admitted a declaration at all,
/// so its absence is an absence of MATCHES.
///
/// One shared sentence would tell an impact reader about matches. The verdict
/// behind it would still be right and the claim in front of them would not, and
/// a surface that renders the wrong noun has drifted from its counterpart in the
/// only place a person actually reads.
fn absence_subject(tool: &str) -> &'static str {
    match tool {
        // Reads no edge class and is language-scoped instead, so what it could
        // not rule out is an index match rather than a dependent.
        "semantic_search" => "matches it did not see",
        // Walks OUTWARD from the focal, so its empty answer is an absence of
        // things this entity reaches rather than of things that reach it.
        "trace_data_flow" => "dependencies it did not see",
        // Its rows ARE the reference edges, and it prints "References to 'X'",
        // so the noun a reader is holding is references. The substrate's own
        // spec subject agrees ("no references to the focal entity were found").
        // Letting it fall through to `dependents` would answer a question about
        // references with a claim about dependents, which is true of the same
        // edges and is not the sentence the reader asked for.
        "find_references" => "references it did not see",
        // Traverses no edge at all: its seed is a name/kind filter over the
        // entity index, so an empty candidate list means nothing MATCHED the
        // seed rather than that nothing is unreachable. Naming dependents here
        // would claim a reachability finding the scan never made.
        "find_dead_code_seeded" => "seed matches it did not see",
        // The whole-repo scan makes the INVERSE claim: "nothing here is
        // unreachable". What it cannot rule out is therefore dead code it never
        // saw, not dependents. It reads no edge class and is not language-scoped
        // (`kin_mcp::negative` says why: a class this build cannot resolve
        // produces MORE candidates, never fewer), so this line renders only when
        // the SUBSTRATE is in doubt, which is the one way a clean scan can lie.
        "dead_code" => "unreachable entities it did not see",
        _ => "dependents",
    }
}

/// Why an absent cross-file class hides this tool's answer, in the direction
/// that tool walked.
///
/// The inbound readers lose a use that reaches the focal; the outbound one loses
/// a dependency the focal reaches. One sentence for both would state the wrong
/// direction on one of them, which is the same drift `absence_subject` exists to
/// stop, one clause later.
fn absence_direction(tool: &str) -> &'static str {
    match tool {
        "trace_data_flow" => {
            "so a dependency this entity reaches in another file could not have been found"
        }
        _ => "so a use reaching this entity from another file could not have been found",
    }
}

/// The edge class in the noun a sentence wants, since the observation keys are
/// plural and the prose is not.
fn edge_class_noun(class: &str) -> &'static str {
    match class {
        "calls" => "call",
        "imports" => "import",
        _ => "reference",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proof_context_unverified_keeps_its_reason_without_inventing_a_clause() {
        let mut tally = kin_model::CallSiteTally::default();
        tally.add(&kin_model::CallerSites::Unverified {
            ledger: kin_model::CallSiteLedger {
                caller: kin_model::EntityId::new(),
                behavior_hash: kin_model::Hash256::from_bytes([0; 32]),
                body_hash: kin_model::Hash256::from_bytes([0; 32]),
                context: kin_model::ResolutionRecordId(uuid::Uuid::from_u128(1)),
                census: 1,
                sites: vec![kin_model::CallSite {
                    offset: 0,
                    length: 1,
                    state: kin_model::CallSiteState::ProvenOutside,
                }],
            },
            reason: "resolver validation failed; no server identified".into(),
        });
        let block = kin_mcp::call_sites::block_json(&tally, "the focal's own body");
        assert!(!block["clauses"][0].as_str().unwrap().contains("; "));
        let payload = json!({
            "references": [],
            "call_sites": block,
            "relation_kinds": ["calls", "imports", "references"],
            "focal_resolution": {"addressed_by": "entity_id", "same_name_candidates": 1},
            "cross_repo": {"status": "not_configured"},
            "caller_arrival": {"state": "accounted"},
            "edge_coverage": {
                "scope": "language", "language": "Python",
                "classes": {"calls": "present", "imports": "present", "references": "present"},
                "reference_enrichment": "available", "budget_exhausted": false
            }
        });
        let envelope = kin_mcp::Envelope::daemon().with_health(&json!({
            "initialized": true, "graph_loaded": true, "graph_entity_count": 3,
        }));
        let negative = kin_mcp::negative::negative_for(
            "find_references",
            &payload,
            &envelope,
            &kin_mcp::verdict::Verdict::pre_negative_gaps(&payload),
        )
        .unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], false);
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason
                .split("; ")
                .any(|clause| clause.starts_with("proof_context_unverified:")),
            "{reason}"
        );
        let rendered = qualify("find_references", &payload, &envelope, "").join("\n");
        assert!(
            rendered.contains("resolver validation failed, no server identified"),
            "{rendered}"
        );
        let result = kin_mcp::finalize_with_envelope(
            kin_mcp::ToolCallResult::text(payload.to_string()),
            envelope,
            "find_references",
        );
        let kin_mcp::ContentBlock::Text { text } = &result.content[0];
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        let factor = value["_kin"]["verdict"]["limiting_factor"]
            .as_str()
            .unwrap();
        assert!(
            factor
                .split("; ")
                .any(|code| code == "proof_context_unverified"),
            "{value}"
        );
        assert!(!factor.contains("unlisted_clause"), "{value}");
    }

    #[test]
    fn a_nonbounding_embedding_flag_does_not_hide_owed_callers() {
        let envelope = kin_mcp::Envelope::daemon().with_health(&json!({
            "initialized": true, "graph_loaded": true, "graph_entity_count": 3,
            "embed_worker_failed": true
        }));
        let payload = json!({
            "entity_impacts": [{"entity_name": "target", "consumer_count": 0}],
            "caller_arrival": {
                "state": "accounted",
                "owed_outside_scope": {"file_count": 1, "callers": 2}
            },
            "edge_coverage": {
                "scope": "language", "language": "Python",
                "classes": {"calls": "present", "imports": "present", "references": "present"},
                "reference_enrichment": "available", "budget_exhausted": false
            }
        });
        let negative =
            kin_mcp::negative::negative_for("impact_analysis", &payload, &envelope, &[]).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], false, "{negative}");
        assert_eq!(negative["degraded_signals"], json!(["embed_worker_failed"]));
        assert_eq!(negative["bounding_signals"], json!([]));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .contains("call_sites_owed"),
            "{negative}"
        );
        let lines = qualify("impact_analysis", &payload, &envelope, "").join("\n");
        assert!(lines.contains("2 caller(s)"), "{lines}");
        assert!(lines.contains("kin daemon sweep"), "{lines}");
        assert!(!lines.contains("embed_worker_failed"), "{lines}");
    }

    #[test]
    fn a_pending_readiness_signal_does_not_hide_the_source_limitation() {
        let envelope = kin_mcp::Envelope::daemon().with_health(&json!({
            "initialized": true, "graph_loaded": true, "graph_entity_count": 3
        }));
        let payload = json!({
            "entity_impacts": [],
            "call_sites": {
                "settled": false,
                "clauses": [
                    "proof_context_unverified: src/user.rs has no validated caller proof",
                    "local_binding_outstanding: src/other.rs still has an unresolved prior binding"
                ]
            },
            "edge_coverage": {
                "scope": "language", "language": "Rust",
                "classes": {"calls": "present", "imports": "present", "references": "present"},
                "reference_enrichment": "unknown", "budget_exhausted": false
            }
        });
        let gaps = kin_mcp::verdict::Verdict::pre_negative_gaps(&payload);
        let negative =
            kin_mcp::negative::negative_for("impact_analysis", &payload, &envelope, &gaps).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], false);
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("src/user.rs"), "{reason}");
        assert!(reason.contains("reference_enrichment_unknown"), "{reason}");
        let lines = qualify("impact_analysis", &payload, &envelope, "");
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("src/user.rs has no validated caller proof"),
            "{rendered}"
        );
        assert!(
            rendered.contains("reference_enrichment_unknown"),
            "{rendered}"
        );
        assert!(
            rendered.contains("src/other.rs still has an unresolved prior binding"),
            "{rendered}"
        );
        assert!(lines.iter().all(|line| line.contains(QUALIFIER_MARK)));
    }

    #[test]
    fn a_bounding_flag_without_a_named_gap_remains_visible() {
        let envelope = kin_mcp::Envelope::daemon().with_health(&json!({
            "initialized": true, "graph_loaded": true, "graph_entity_count": 3,
            "mass_deletion_blocked": true, "embed_worker_failed": true
        }));
        let payload = json!({
            "chain": [],
            "edge_coverage": {
                "scope": "language", "language": "Python",
                "classes": {"calls": "present", "imports": "present", "references": "present"},
                "reference_enrichment": "available", "budget_exhausted": false
            }
        });
        let negative =
            kin_mcp::negative::negative_for("trace_data_flow", &payload, &envelope, &[]).unwrap();
        assert_eq!(
            negative["bounding_signals"],
            json!(["mass_deletion_blocked"])
        );
        assert!(!negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("mass_deletion_blocked"));
        let lines = qualify("trace_data_flow", &payload, &envelope, "").join("\n");
        assert!(lines.contains("mass_deletion_blocked"), "{lines}");
        assert!(!lines.contains("embed_worker_failed"), "{lines}");
    }

    #[test]
    fn missing_federation_authority_is_not_an_unconfigured_scope() {
        for reason in [
            "cross_repo_authority_missing: no authority observation",
            "cross_repo_not_configured; cross_repo_authority_missing",
            "cross_repo_unavailable: lookup failed",
        ] {
            assert!(!only_unconfigured_federation(
                &json!({"trust_reason": reason})
            ));
        }
        assert!(only_unconfigured_federation(&json!({
            "trust_reason": "cross_repo_not_configured: local repository"
        })));
    }

    #[test]
    fn empty_references_distinguish_missing_authority_from_local_scope() {
        let envelope = kin_mcp::Envelope::daemon().with_health(&json!({
            "initialized": true, "graph_loaded": true, "graph_generation": 1
        }));
        let mut payload = json!({
            "focal_entity": {"id": "00000000-0000-0000-0000-000000000001",
                             "kind": "Function", "name": "unused"},
            "focal_resolution": {"addressed_by": "name", "same_name_candidates": 1},
            "references": [],
            "edge_coverage": {
                "scope": "language", "language": "Rust",
                "requested_classes": ["calls", "imports", "references"],
                "classes": {"calls": "present", "imports": "present", "references": "present"},
                "cross_file_classes": ["calls", "imports", "references"],
                "reference_enrichment": "available", "budget_exhausted": false,
                "entities_examined": 2
            }
        });
        let lines = qualify("find_references", &payload, &envelope, "");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("find_references did not report cross-repo authority")),
            "{lines:?}"
        );
        payload["cross_repo"] = json!({"status": "not_configured"});
        assert!(qualify("find_references", &payload, &envelope, "").is_empty());
    }
}
