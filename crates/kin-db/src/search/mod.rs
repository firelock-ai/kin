// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod text;

pub use text::{
    entity_fields, entity_fields_with_extra, opaque_artifact_fields, resolve_roles,
    shallow_file_fields, structured_artifact_fields, ScoredHit, TextIndex,
};
