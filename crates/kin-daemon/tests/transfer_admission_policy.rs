// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source contract: every native transfer receiver in this daemon admits packs
//! through the one wrapper that runs the admission-provenance policy.
//!
//! The defect this pins is a receiver that admits transported history and
//! leaves the store describing itself by a hydration creation record that
//! predates it, so `kin graph status`, `kin doctor` and the `_kin` envelope all
//! read current over history whose authoring version nothing recorded.
//!
//! `kin_remote::repository_transfer::apply_repository_transfer_pack` is
//! crate-visible, so the compiler already refuses a policy-free admission from
//! here. What the compiler cannot see is a new site calling the hooked function
//! directly with an empty policy, which compiles and reads like every other
//! admission. That is what this file refuses.
//!
//! It lives outside `api.rs` on purpose. A guard whose own source sits inside
//! the file it scans matches itself, so it passes on a tree where the thing it
//! guards has already been deleted.

/// The daemon's HTTP surface, read at compile time so the assertion cannot
/// drift onto a stale copy or a path that no longer exists.
const API_SOURCE: &str = include_str!("../src/api.rs");

/// The one function allowed to name the hooked admission.
const WRAPPER: &str = "fn apply_received_repository_transfer_pack(";

/// The hooked admission itself, as an invocation rather than a mention.
const HOOKED_CALL: &str = "apply_repository_transfer_pack_with_pre_commit(";

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The scan reads the file it means to read. Without this, every assertion
/// below is satisfied by an empty string.
#[test]
fn the_guard_reads_the_daemon_api_source() {
    assert!(
        API_SOURCE.len() > 100_000,
        "api.rs read as {} bytes, which is not the file this guard exists to scan",
        API_SOURCE.len()
    );
    assert_eq!(
        occurrences(API_SOURCE, WRAPPER),
        1,
        "expected exactly one definition of the admission wrapper"
    );
    assert_eq!(
        occurrences(
            API_SOURCE,
            "fn a_name_no_transfer_receiver_in_this_daemon_has_ever_carried("
        ),
        0,
        "the must-miss control matched, so a hit here proves nothing"
    );
}

/// The whole contract in one line: the hooked admission is named once, and the
/// wrapper is what names it.
#[test]
fn only_the_admission_wrapper_names_the_hooked_transfer_apply() {
    let calls = occurrences(API_SOURCE, HOOKED_CALL);
    assert_eq!(
        calls, 1,
        "{HOOKED_CALL} is invoked {calls} times in api.rs; every native receiver must go through \
         the wrapper so the admission-provenance policy cannot be skipped by a new site"
    );

    let wrapper_start = API_SOURCE
        .find(WRAPPER)
        .expect("the wrapper definition was asserted present above");
    // A rustfmt-formatted item ends at the first column-zero closing brace after
    // its signature; every brace inside the body is indented.
    let wrapper_end = API_SOURCE[wrapper_start..]
        .find("\n}\n")
        .map(|offset| wrapper_start + offset)
        .expect("the wrapper definition has no closing brace");
    let call_at = API_SOURCE
        .find(HOOKED_CALL)
        .expect("the single invocation was asserted present above");
    assert!(
        call_at > wrapper_start && call_at < wrapper_end,
        "the hooked admission is invoked outside the wrapper (wrapper spans {wrapper_start}..\
         {wrapper_end}, call at {call_at})"
    );
}

/// Both native receivers exist and both use the wrapper.
///
/// The count above would also be satisfied by a tree where one receiver stopped
/// admitting anything at all, which is a different defect wearing the same
/// green. Inbound receive is where a `kin push` lands; `pull_into_replica` is
/// shared by CLI pull and native clone, once per pack of a segmented gap.
#[test]
fn both_native_receivers_admit_through_the_wrapper() {
    let definition = 1;
    let call_sites = occurrences(API_SOURCE, "apply_received_repository_transfer_pack(") - definition;
    assert!(
        call_sites >= 2,
        "expected the inbound receive route and pull_into_replica to admit through the wrapper, \
         found {call_sites} call sites"
    );
    for receiver in [
        "async fn repo_transfer_receive(",
        "pub(crate) async fn pull_into_replica(",
    ] {
        assert_eq!(
            occurrences(API_SOURCE, receiver),
            1,
            "the native receiver {receiver} is not in api.rs, so the count above is measuring a \
             tree this guard was not written for"
        );
    }
}
