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
//! The tool name is load-bearing rather than decorative. `kin trace` builds a
//! context pack, so it declares `get_context_pack` and NOT `trace_data_flow`,
//! which describes a different walk; `kin search` declares `semantic_search`,
//! which reads no edge class at all and is gated on the language scope instead.
//! Naming the wrong one gates a command on a declaration describing evidence it
//! never gathered, which is the failure `IMPACT_REFERENCE_KINDS` already warns
//! about one level down.
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
    let Some(negative) = kin_mcp::negative::negative_for(tool, payload, envelope, &[]) else {
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
    // verdict publishes rather than recomputed. Listing every absent class would
    // tell a reader their import edges were the problem on a store where imports
    // never mattered: Kin's linker mints no entity-level `Imports` relation on
    // any language, so that class reads absent on healthy graphs too.
    let missing: Vec<&'static str> = decided_by(tool, payload, envelope)
        .iter()
        .filter(|class| state_of(class) == Some("absent"))
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
    if missing.is_empty() {
        let disclosed = negative
            .get("degraded_signals")
            .and_then(serde_json::Value::as_array)
            .map(|signals| {
                signals
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|disclosed| !disclosed.is_empty());
        return vec![match disclosed {
            Some(disclosed) => format!(
                "{indent}Kin cannot rule out matches it did not see: this answer carries \
                 [{disclosed}], so it may not reflect current truth."
            ),
            None => format!(
                "{indent}Kin cannot rule out matches it did not see: this answer's coverage \
                 could not be established."
            ),
        }];
    }

    let mut said = vec![format!(
        "{indent}Kin cannot rule out dependents: this graph holds no cross-file {} edges for \
         {language}, so a use reaching this entity from another file could not have been found.",
        missing.join(" or ")
    )];
    if !present.is_empty() {
        said.push(format!(
            "{indent}Cross-file {} edges exist but do not stand in for {} edges.",
            present.join(" and "),
            missing.join(" or ")
        ));
    }
    said
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

/// The edge class in the noun a sentence wants, since the observation keys are
/// plural and the prose is not.
fn edge_class_noun(class: &str) -> &'static str {
    match class {
        "calls" => "call",
        "imports" => "import",
        _ => "reference",
    }
}
