// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded retries inside one enrichment pass. A file still unanswered after
//! these attempts remains owed; its persisted backoff decides the next pass.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use kin_model::{FilePathId, LanguageId};

const RETRIES_PER_FILE: u32 = 1;
const USES_TYPE_RETRIES_PER_FILE: u32 = 2;
const CRASHES_WITHOUT_COMPLETING_A_FILE: usize = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Retry {
    Queued,
    Owed,
    LanguageUnavailable,
}

pub(crate) struct SweepFiles {
    pending: VecDeque<FilePathId>,
    retries: HashMap<FilePathId, u32>,
    crashes: HashMap<LanguageId, usize>,
}

impl SweepFiles {
    pub(crate) fn new(files: impl IntoIterator<Item = FilePathId>) -> Self {
        let mut files: Vec<_> = files.into_iter().collect();
        // Hash-map insertion order must not decide which files get a warm
        // server, or which ones a stopped pass has already finished.
        files.sort_by(|left, right| left.0.cmp(&right.0));
        Self {
            pending: files.into(),
            retries: HashMap::new(),
            crashes: HashMap::new(),
        }
    }

    pub(crate) fn next(&mut self) -> Option<FilePathId> {
        self.pending.pop_front()
    }

    pub(crate) fn is_retry(&self, file: &FilePathId) -> bool {
        self.retry_count(file) > 0
    }

    pub(crate) fn retry_count(&self, file: &FilePathId) -> u32 {
        self.retries.get(file).copied().unwrap_or(0)
    }

    pub(crate) fn completed(&mut self, language: LanguageId) {
        // A large repository may need several server lifetimes. Only deaths
        // without completing a file spend the language's restart allowance.
        self.crashes.remove(&language);
    }

    pub(crate) fn failed(
        &mut self,
        file: &FilePathId,
        language: LanguageId,
        server_died: bool,
        uses_type_timeout_budget: Option<Duration>,
    ) -> Retry {
        if server_died {
            let crashes = self.crashes.entry(language).or_default();
            *crashes += 1;
            if *crashes >= CRASHES_WITHOUT_COMPLETING_A_FILE {
                return Retry::LanguageUnavailable;
            }
        }
        // Only an actual aggregate uses-type timeout earns the remaining
        // larger allowance. A dead server and other failed arms retain their
        // original retry limits. The maximum allowance is tried once, even
        // when persisted debt started this sweep at that allowance.
        let limit = match uses_type_timeout_budget.filter(|_| !server_died) {
            Some(budget) if budget < crate::owed_enrichment::USES_TYPE_MAX_BUDGET => {
                USES_TYPE_RETRIES_PER_FILE
            }
            Some(_) => return Retry::Owed,
            None => RETRIES_PER_FILE,
        };
        let retries = self.retries.entry(file.clone()).or_default();
        if *retries >= limit {
            return Retry::Owed;
        }
        *retries += 1;
        if server_died {
            // The caller retired this server. Retry the interrupted file on
            // its replacement before walking any other file.
            self.pending.push_front(file.clone());
        } else {
            // Give a live but overloaded server the rest of the pass before
            // asking the same file again.
            self.pending.push_back(file.clone());
        }
        Retry::Queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> FilePathId {
        FilePathId(path.into())
    }

    #[test]
    fn a_dead_server_retries_its_file_before_advancing() {
        let mut files = SweepFiles::new([file("b.ts"), file("a.ts")]);
        let a = files.next().unwrap();
        assert_eq!(a, file("a.ts"));
        assert_eq!(
            files.failed(&a, LanguageId::TypeScript, true, None),
            Retry::Queued
        );
        assert_eq!(files.next(), Some(a.clone()));
        files.completed(LanguageId::TypeScript);
        assert_eq!(files.next(), Some(file("b.ts")));
        assert_eq!(files.next(), None);
    }

    #[test]
    fn a_timeout_waits_for_other_files_and_never_loops_on_one_file() {
        let mut files = SweepFiles::new([file("b.py"), file("a.py")]);
        let a = files.next().unwrap();
        assert_eq!(
            files.failed(&a, LanguageId::Python, false, None),
            Retry::Queued
        );
        assert_eq!(files.next(), Some(file("b.py")));
        assert_eq!(files.next(), Some(a.clone()));
        assert_eq!(
            files.failed(&a, LanguageId::Python, false, None),
            Retry::Owed
        );
        assert_eq!(files.next(), None);
    }

    #[test]
    fn a_uses_type_timeout_does_not_extend_a_dead_servers_retry_allowance() {
        let mut files = SweepFiles::new([file("a.py")]);
        let a = files.next().unwrap();
        assert_eq!(
            files.failed(&a, LanguageId::Python, true, Some(Duration::from_secs(5))),
            Retry::Queued
        );
        assert_eq!(files.next(), Some(a.clone()));
        assert_eq!(
            files.failed(&a, LanguageId::Python, true, Some(Duration::from_secs(15))),
            Retry::Owed
        );
        assert_eq!(files.next(), None);
    }

    #[test]
    fn poison_files_bound_restarts_without_blocking_other_languages() {
        let mut files = SweepFiles::new([file("a.ts"), file("b.ts"), file("c.py")]);
        let a = files.next().unwrap();
        assert_eq!(
            files.failed(&a, LanguageId::TypeScript, true, None),
            Retry::Queued
        );
        assert_eq!(files.next(), Some(a.clone()));
        assert_eq!(
            files.failed(&a, LanguageId::TypeScript, true, None),
            Retry::Owed
        );
        let b = files.next().unwrap();
        assert_eq!(
            files.failed(&b, LanguageId::TypeScript, true, None),
            Retry::LanguageUnavailable
        );
        let c = files.next().unwrap();
        assert_eq!(
            files.failed(&c, LanguageId::Python, true, None),
            Retry::Queued
        );
        assert_eq!(files.next(), Some(c));
    }

    #[test]
    fn completed_files_allow_a_large_graph_to_use_more_server_lifetimes() {
        let mut files = SweepFiles::new((0..10).map(|n| file(&format!("{n:02}.ts"))));
        for n in 0..10 {
            let current = files.next().unwrap();
            assert_eq!(current, file(&format!("{n:02}.ts")));
            assert_eq!(
                files.failed(&current, LanguageId::TypeScript, true, None),
                Retry::Queued
            );
            assert_eq!(files.next(), Some(current));
            files.completed(LanguageId::TypeScript);
        }
        assert_eq!(files.next(), None);
    }
}
