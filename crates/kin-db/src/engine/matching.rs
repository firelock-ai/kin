/// Shared name-matching logic for pattern queries.
///
/// Supports three modes:
/// - `*suffix` — names ending with `suffix`
/// - `prefix*` — names starting with `prefix`
/// - `substring` — names containing the pattern (default)
///
/// All comparisons are case-insensitive: both `name` and `pattern`
/// are lowercased before matching.
pub fn name_matches(name: &str, pattern: &str) -> bool {
    let name_lc = name.to_lowercase();
    let pat = pattern.to_lowercase();

    if let Some(suffix) = pat.strip_prefix('*') {
        name_lc.ends_with(suffix)
    } else if let Some(prefix) = pat.strip_suffix('*') {
        name_lc.starts_with(prefix)
    } else {
        name_lc.contains(&*pat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_match() {
        assert!(name_matches("getUserById", "user"));
        assert!(name_matches("getUserById", "User"));
        assert!(!name_matches("deletePost", "user"));
    }

    #[test]
    fn prefix_match() {
        assert!(name_matches("getUserById", "get*"));
        assert!(name_matches("getPost", "get*"));
        assert!(!name_matches("deletePost", "get*"));
    }

    #[test]
    fn suffix_match() {
        assert!(name_matches("getUserById", "*byid"));
        assert!(!name_matches("deletePost", "*byid"));
    }

    #[test]
    fn case_insensitive() {
        assert!(name_matches("MyFunction", "myfunction"));
        assert!(name_matches("MyFunction", "MY*"));
        assert!(name_matches("MyFunction", "*FUNCTION"));
    }
}
