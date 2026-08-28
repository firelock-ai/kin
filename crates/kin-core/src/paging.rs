// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// Opaque cursor for a held locate ranking.
///
/// Version 2 carries the absolute offset of the next row independently from the
/// preferred width of the next page. That separation lets a caller change page
/// width without repeating or skipping rows, and lets the response budget move
/// the offset backward by exactly the suffix it withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocateCursor {
    pub key: String,
    pub page: usize,
    pub next_offset: Option<usize>,
    pub page_size: Option<usize>,
}

impl LocateCursor {
    /// Encode a version-2 cursor when the absolute offset and width are known.
    /// A cursor without those fields encodes in the released legacy shape.
    pub fn encode(&self) -> String {
        match (self.next_offset, self.page_size.filter(|size| *size > 0)) {
            (Some(next_offset), Some(page_size)) => format!(
                "v2.{}.{}.{}.{}",
                self.key, self.page, next_offset, page_size
            ),
            _ => format!("{}.{}", self.key, self.page),
        }
    }

    /// Decode the released `<key>.<page>` shape and the offset-safe v2 shape.
    /// Unknown intermediate shapes fail loud instead of guessing field meaning.
    pub fn decode(token: &str) -> Option<Self> {
        let parts = token.trim().split('.').collect::<Vec<_>>();
        let cursor = match parts.as_slice() {
            ["v2", key, page, next_offset, page_size] => Self {
                key: (*key).to_string(),
                page: page.parse::<usize>().ok()?,
                next_offset: Some(next_offset.parse::<usize>().ok()?),
                page_size: Some(page_size.parse::<usize>().ok().filter(|size| *size > 0)?),
            },
            [key, page] => Self {
                key: (*key).to_string(),
                page: page.parse::<usize>().ok()?,
                next_offset: None,
                page_size: None,
            },
            _ => return None,
        };
        // Every response serializer advances `page` when more rows remain. A
        // public token can be edited independently of its absolute offset, so
        // accepting `usize::MAX` here would let an otherwise valid cached
        // continuation overflow on `page + 1`. Such a page was never minted by
        // Kin and cannot be continued honestly; fail the token before routing.
        (!cursor.key.is_empty() && cursor.page.checked_add(1).is_some()).then_some(cursor)
    }

    /// Rebase a newly minted cursor after the response budget withheld a suffix
    /// of the page. Returns false for a legacy or inconsistent cursor so callers
    /// can retain the rows instead of trimming without a recovery path.
    pub fn rebase_after_withheld(&mut self, withheld: usize, kept: usize) -> bool {
        if withheld == 0 || kept == 0 {
            return false;
        }
        let Some(next_offset) = self.next_offset else {
            return false;
        };
        let Some(rebased) = next_offset.checked_sub(withheld) else {
            return false;
        };
        self.next_offset = Some(rebased);
        self.page_size = Some(kept);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_cursor_round_trips_v2_and_released_legacy() {
        let v2 = LocateCursor {
            key: "deadbeef".to_string(),
            page: 3,
            next_offset: Some(18),
            page_size: Some(6),
        };
        assert_eq!(v2.encode(), "v2.deadbeef.3.18.6");
        assert_eq!(LocateCursor::decode(&v2.encode()), Some(v2));

        let legacy = LocateCursor::decode("deadbeef.3").expect("legacy cursor");
        assert_eq!(legacy.key, "deadbeef");
        assert_eq!(legacy.page, 3);
        assert_eq!(legacy.next_offset, None);
        assert_eq!(legacy.page_size, None);
        assert_eq!(legacy.encode(), "deadbeef.3");

        for malformed in [
            "",
            "nodelimiter",
            ".3",
            "v2.deadbeef.nope.18.6",
            "v2.deadbeef.3.nope.6",
            "v2.deadbeef.3.18.0",
            "deadbeef.3.6",
        ] {
            assert!(LocateCursor::decode(malformed).is_none(), "{malformed}");
        }

        for overflow in [
            format!("deadbeef.{}", usize::MAX),
            format!("v2.deadbeef.{}.18.6", usize::MAX),
        ] {
            assert!(
                LocateCursor::decode(&overflow).is_none(),
                "a cursor page must leave room for the next continuation: {overflow}"
            );
        }
    }

    #[test]
    fn budget_rebase_moves_only_the_absolute_offset() {
        let mut cursor = LocateCursor {
            key: "deadbeef".to_string(),
            page: 2,
            next_offset: Some(12),
            page_size: Some(6),
        };
        assert!(cursor.rebase_after_withheld(4, 2));
        assert_eq!(cursor.page, 2);
        assert_eq!(cursor.next_offset, Some(8));
        assert_eq!(cursor.page_size, Some(2));

        let mut legacy = LocateCursor::decode("deadbeef.2").unwrap();
        assert!(!legacy.rebase_after_withheld(4, 2));
        assert_eq!(legacy.encode(), "deadbeef.2");
    }
}
