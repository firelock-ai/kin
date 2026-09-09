// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared byte formatting for daemon memory diagnostics.

/// Render a byte count the way daemon-memory diagnostics read it: whole
/// mebibytes below a gibibyte, one decimal place at and above it.
pub(super) fn human_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_gib_values_are_whole_mebibytes() {
        assert_eq!(human_bytes(0), "0 MiB");
        assert_eq!(human_bytes(82 * 1024 * 1024), "82 MiB");
    }

    #[test]
    fn gib_and_above_carry_one_decimal() {
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(human_bytes(12 * 1024 * 1024 * 1024), "12.0 GiB");
    }
}
