// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Apply resolves one immutable attempt; Save may keep newer editing text.
use super::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

impl DraftStore {
    fn prepare_apply(&self, request: DraftApply) -> Result<PendingDraftApply> {
        if request.expected_revision == 0 {
            return Err(refuse(
                "draft_invalid_request",
                "expected_revision must be positive",
            ));
        }
        let locked = self.locked(true)?.expect("write opened store");
        let current = self.load(&locked, request.draft_id, None)?;
        // A new attempt is appended exactly after the requested revision.
        // Resolve that immutable invocation before consulting a newer pending
        // attempt. Otherwise an old successful retry could execute new work.
        if let Some(number) = request.expected_revision.checked_add(1) {
            if locked
                .records
                .get(&request.draft_id)
                .is_some_and(|revisions| revisions.contains_key(&number))
            {
                let original = self.load(&locked, request.draft_id, Some(number))?;
                if let Some(attempt) = &original.draft.pending_apply {
                    if attempt.requested_revision == request.expected_revision
                        && attempt.session_id == request.session_id
                    {
                        self.replay(
                            &locked,
                            request.draft_id,
                            number,
                            &original.draft.request_hash,
                        )?;
                        return Ok(attempt.clone());
                    }
                }
            }
        }
        if let Some(attempt) = &current.draft.pending_apply {
            if request.expected_revision < attempt.requested_revision
                || request.expected_revision > current.draft.revision
            {
                return Err(refuse("draft_revision_conflict", "This invocation does not identify the current pending attempt. Read its original requested_revision and session_id to resolve it."));
            }
            // The latest body may differ. Only the persisted original can run.
            self.replay(
                &locked,
                request.draft_id,
                current.draft.revision,
                &current.draft.request_hash,
            )?;
            return Ok(attempt.clone());
        }
        if let Some(applied) = &current.draft.applied_receipt {
            if applied.attempt.draft_revision == current.draft.content_revision {
                return Ok(applied.attempt.clone());
            }
        }
        if request.expected_revision != current.draft.revision {
            return Err(refuse(
                "draft_revision_conflict",
                "Read the latest saved draft before starting a new Apply attempt.",
            ));
        }
        let mut draft = current.draft;
        let request_id = format!(
            "draft:{}:{}:{}",
            draft.draft_id,
            draft.content_revision,
            uuid::Uuid::new_v4()
        );
        let arguments = json!({"session_id":request.session_id,"request_id":request_id,
            "scope":"repository", "summary":"Apply saved entity draft",
            "operations":[{"verb":"update","target":draft.scope.entity_id,"body":draft.body,
                "payload":{"EntitySourceBase":draft.original_source_base},"description":"Apply saved entity draft"}]});
        let attempt = PendingDraftApply {
            requested_revision: request.expected_revision,
            draft_revision: draft.content_revision,
            session_id: request.session_id,
            request_id,
            arguments,
        };
        draft.revision = draft
            .revision
            .checked_add(1)
            .ok_or_else(|| refuse("draft_quota", "Draft revision space exhausted"))?;
        draft.previous_record_hash = Some(current.record_hash);
        draft.request_hash = digest(&("apply", &request, &attempt))?;
        draft.pending_apply = Some(attempt.clone());
        self.publish(&locked, DraftEnvelope::new(draft)?)?;
        Ok(attempt)
    }

    fn record_receipt(
        &self,
        id: uuid::Uuid,
        attempt: &PendingDraftApply,
        receipt: Value,
    ) -> Result<EntityDraft> {
        let locked = self.locked(true)?.expect("write opened store");
        let current = self.load(&locked, id, None)?;
        if let Some(applied) = &current.draft.applied_receipt {
            if &applied.attempt == attempt {
                if applied.receipt != receipt {
                    return Err(refuse(
                        "draft_corrupt",
                        "The saved Apply receipt disagrees with repository authority.",
                    ));
                }
                self.replay(
                    &locked,
                    id,
                    current.draft.revision,
                    &current.draft.request_hash,
                )?;
                return Ok(current.draft);
            }
        }
        if current.draft.pending_apply.as_ref() != Some(attempt) {
            // Later attempts do not erase earlier acknowledged receipts.
            for (&number, _) in locked
                .records
                .get(&id)
                .expect("loaded draft")
                .range((attempt.requested_revision.saturating_add(1))..)
                .rev()
            {
                let old = self.load(&locked, id, Some(number))?;
                if let Some(applied) = &old.draft.applied_receipt {
                    if &applied.attempt == attempt {
                        if applied.receipt != receipt {
                            return Err(refuse(
                                "draft_corrupt",
                                "Historical draft receipt disagrees with repository authority.",
                            ));
                        }
                        self.replay(&locked, id, number, &old.draft.request_hash)?;
                        return Ok(current.draft);
                    }
                }
            }
            return Err(refuse("draft_apply_recovery_required", "The latest draft does not carry this exact pending attempt. Keep the original request and receipt for recovery."));
        }
        self.phase(DraftWritePhase::BeforeApplyReceipt)?;
        let mut draft = current.draft;
        draft.revision = draft
            .revision
            .checked_add(1)
            .ok_or_else(|| refuse("draft_quota", "Draft revision space exhausted"))?;
        draft.previous_record_hash = Some(current.record_hash);
        draft.request_hash = digest(&("apply_receipt", attempt, &receipt))?;
        draft.pending_apply = None;
        draft.applied_receipt = Some(AppliedDraftReceipt {
            attempt: attempt.clone(),
            receipt,
        });
        Ok(self.publish(&locked, DraftEnvelope::new(draft)?)?.draft)
    }
}

fn error_result(
    error: DraftError,
    id: Option<uuid::Uuid>,
    attempt: Option<&PendingDraftApply>,
) -> kin_mcp::ToolCallResult {
    kin_mcp::ToolCallResult::error(json!({"schema":"kin.entity.draft.apply_pending.v1",
        "code":error.code,"message":error.message,"draft_id":id,"attempt":attempt,
        "receipt_saved":false,
        "remedy":"Keep the draft and retry Apply to resolve the exact original attempt. A stale source base requires a fresh draft from an explicit current source read; existing text and history remain available."}).to_string())
}

/// Keep receipt persistence running if an HTTP caller stops listening. Process
/// death still leaves the exact attempt durable for keyed receipt recovery.
pub(crate) async fn call(
    state: Arc<crate::state::DaemonState>,
    arguments: HashMap<String, Value>,
    authenticated: bool,
) -> crate::mcp_commit::McpCommitOutcome {
    tokio::spawn(run(state, arguments, authenticated))
        .await
        .map_err(|error| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
            )
        })
}

async fn run(
    state: Arc<crate::state::DaemonState>,
    arguments: HashMap<String, Value>,
    authenticated: bool,
) -> kin_mcp::ToolCallResult {
    let prepared = (|| -> Result<(DraftStore, DraftApply)> {
        if !authenticated {
            return Err(refuse(
                "draft_authentication_required",
                "Apply requires an enforced local bearer owner.",
            ));
        }
        if !state
            .is_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
            || state.storage_backend.is_some()
        {
            return Err(refuse(
                "draft_repository_unavailable",
                "Apply requires an initialized local repository daemon.",
            ));
        }
        require_durability_platform()?;
        let request: DraftApply =
            serde_json::from_value(serde_json::to_value(arguments).map_err(io)?)
                .map_err(|error| refuse("draft_invalid_request", error.to_string()))?;
        let store = DraftStore::from_state(&state, DraftOwner::LocalBearerV1)?;
        Ok((store, request))
    })();
    let (store, request) = match prepared {
        Ok(value) => value,
        Err(error) => return error_result(error, None, None),
    };
    let id = request.draft_id;
    let prepared = tokio::task::spawn_blocking(move || {
        store.prepare_apply(request).map(|attempt| (store, attempt))
    })
    .await;
    let (store, attempt) = match prepared {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return error_result(error, Some(id), None),
        Err(error) => return error_result(io(error), Some(id), None),
    };
    if let Err(error) = store.phase(DraftWritePhase::BeforeApplyDispatch) {
        return error_result(error, Some(id), Some(&attempt));
    }
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "X-Kin-Session",
        attempt
            .session_id
            .to_string()
            .parse()
            .expect("UUID is a header value"),
    );
    let arguments = match serde_json::from_value(attempt.arguments.clone()) {
        Ok(value) => value,
        Err(error) => {
            return error_result(
                refuse("draft_corrupt", error.to_string()),
                Some(id),
                Some(&attempt),
            )
        }
    };
    let outcome = crate::mcp_mutate::call(state, headers, arguments, authenticated).await;
    let result = match outcome {
        Ok(value) => value,
        Err((status, message)) => {
            return error_result(
                io(format!("Apply transport outcome {status}: {message}")),
                Some(id),
                Some(&attempt),
            )
        }
    };
    if result.is_error == Some(true) {
        // An error may carry a published receipt needing runtime recovery. Do
        // not claim nonpublication or replace the original attempt in either case.
        return kin_mcp::ToolCallResult::error(json!({"schema":"kin.entity.draft.apply_pending.v1",
            "code":"draft_apply_unresolved","draft_id":id,"attempt":attempt,"receipt_saved":false,
            "mutation_result":result,
            "remedy":"Retry Apply to resolve this original attempt. For a stale source base, create a fresh draft from a current source read and preserve this draft's text/history. Save may preserve newer text while this attempt remains bound."}).to_string());
    }
    let receipt = (|| -> Result<Value> {
        let [kin_mcp::ContentBlock::Text { text }] = result.content.as_slice() else {
            return Err(refuse(
                "draft_apply_recovery_required",
                "Mutation success did not contain one authoritative receipt.",
            ));
        };
        let mut receipt: Value = serde_json::from_str(text).map_err(io)?;
        if receipt["schema"] != "kin.mutate.receipt.v1"
            || receipt["status"] != "committed"
            || receipt["request_id"] != attempt.request_id
            || receipt["repository_id"] != store.context.repository_id().to_string()
        {
            return Err(refuse(
                "draft_apply_recovery_required",
                "Mutation response did not match this draft's original request and repository.",
            ));
        }
        receipt
            .as_object_mut()
            .expect("receipt schema checked")
            .remove("already_applied");
        Ok(receipt)
    })();
    let receipt = match receipt {
        Ok(value) => value,
        Err(error) => return error_result(error, Some(id), Some(&attempt)),
    };
    let save_attempt = attempt.clone();
    let save_receipt = receipt.clone();
    let saved =
        tokio::task::spawn_blocking(move || store.record_receipt(id, &save_attempt, save_receipt))
            .await;
    match saved {
        Ok(Ok(draft)) => kin_mcp::ToolCallResult::text(
            json!({"schema":"kin.entity.draft.applied.v1",
            "draft_id":id,"requested_revision":attempt.requested_revision,"applied_draft_revision":attempt.draft_revision,
            "current_text_applied":draft.content_revision == attempt.draft_revision,
            "receipt_saved":true,"receipt":receipt,"draft":draft})
            .to_string(),
        ),
        other => {
            let error = match other {
                Ok(Err(error)) => error,
                Err(error) => io(error),
                _ => unreachable!(),
            };
            kin_mcp::ToolCallResult::error(json!({"schema":"kin.entity.draft.apply_pending.v1",
                "code":"draft_apply_receipt_not_saved","message":error.to_string(),"draft_id":id,
                "attempt":attempt,"repository_source_applied":true,"receipt_saved":false,"receipt":receipt,
                "remedy":"Repository publication succeeded but its draft receipt was not acknowledged. Retry Apply with this original attempt; do not create a replacement mutation."}).to_string())
        }
    }
}
