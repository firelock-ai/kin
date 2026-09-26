// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! PEP 440 versions and specifiers, and PEP 508 environment markers, evaluated
//! for a target Python and platform rather than for the host.
//!
//! A lockfile holds the packages every supported environment needs, each
//! guarded by a marker (`python_version < "3.11"`, `sys_platform == "win32"`).
//! Choosing the ones the analysis environment needs means evaluating those
//! markers for the Python version the repository pins and the platform the
//! server runs on. Nothing here runs Python.

use std::cmp::Ordering;

/// A PEP 440 version.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Vec<LocalPart>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LocalPart {
    // Declared first: an alphanumeric segment sorts before a numeric one.
    Text(String),
    Number(u64),
}

impl Version {
    /// Parse a version the way PEP 440 normalizes it: case aside, with an
    /// optional `v`, and `-`, `_` or `.` before a pre, post or dev part.
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim().to_ascii_lowercase();
        let text = text.strip_prefix('v').unwrap_or(&text);
        let (public, local) = match text.split_once('+') {
            Some((public, local)) => (public, Some(local)),
            None => (text, None),
        };
        let (epoch, rest) = match public.split_once('!') {
            Some((epoch, rest)) => (epoch.parse().ok()?, rest),
            None => (0, public),
        };
        let bytes = rest.as_bytes();
        let mut index = 0;
        let mut release = Vec::new();
        loop {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if start == index {
                return None;
            }
            release.push(rest[start..index].parse().ok()?);
            if index + 1 < bytes.len() && bytes[index] == b'.' && bytes[index + 1].is_ascii_digit()
            {
                index += 1;
            } else {
                break;
            }
        }
        let mut version = Version {
            epoch,
            release,
            pre: None,
            post: None,
            dev: None,
            local: Vec::new(),
        };
        let mut rest = &rest[index..];
        // Each suffix at most once, in the order pre, post, dev.
        fn take_separator(text: &str) -> &str {
            text.strip_prefix(['.', '-', '_']).unwrap_or(text)
        }
        let take_number = |text: &str| -> (Option<u64>, usize) {
            let body = text.strip_prefix(['.', '-', '_']).unwrap_or(text);
            let skipped = text.len() - body.len();
            let digits = body.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                (None, 0)
            } else {
                (body[..digits].parse().ok(), skipped + digits)
            }
        };
        let after = take_separator(rest);
        for (word, kind) in [
            ("alpha", 0u8),
            ("beta", 1),
            ("preview", 2),
            ("pre", 2),
            ("rc", 2),
            ("a", 0),
            ("b", 1),
            ("c", 2),
        ] {
            if let Some(tail) = after.strip_prefix(word) {
                let (number, used) = take_number(tail);
                version.pre = Some((kind, number.unwrap_or(0)));
                rest = &tail[used..];
                break;
            }
        }
        let after = take_separator(rest);
        let mut post_matched = false;
        for word in ["post", "rev", "r"] {
            if let Some(tail) = after.strip_prefix(word) {
                let (number, used) = take_number(tail);
                version.post = Some(number.unwrap_or(0));
                rest = &tail[used..];
                post_matched = true;
                break;
            }
        }
        if !post_matched {
            if let Some(tail) = rest.strip_prefix('-') {
                let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
                if digits > 0 {
                    version.post = tail[..digits].parse().ok();
                    rest = &tail[digits..];
                }
            }
        }
        let after = take_separator(rest);
        if let Some(tail) = after.strip_prefix("dev") {
            let (number, used) = take_number(tail);
            version.dev = Some(number.unwrap_or(0));
            rest = &tail[used..];
        }
        if !rest.is_empty() {
            return None;
        }
        if let Some(local) = local {
            if local.is_empty() {
                return None;
            }
            for part in local.split(['.', '-', '_']) {
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return None;
                }
                version.local.push(match part.parse() {
                    Ok(number) => LocalPart::Number(number),
                    Err(_) => LocalPart::Text(part.to_string()),
                });
            }
        }
        Some(version)
    }

    /// The release segment, `[3, 11, 4]` for `3.11.4`.
    pub fn release(&self) -> &[u64] {
        &self.release
    }

    /// Whether this is a pre-release or development release.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    fn release_at(&self, index: usize) -> u64 {
        self.release.get(index).copied().unwrap_or(0)
    }

    fn compare_release(&self, other: &Version) -> Ordering {
        let length = self.release.len().max(other.release.len());
        (0..length)
            .map(|index| self.release_at(index).cmp(&other.release_at(index)))
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
    }

    /// The version without its local part.
    fn public(&self) -> Version {
        Version {
            local: Vec::new(),
            ..self.clone()
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // PEP 440's order: a dev release of a final release precedes its
        // pre-releases; a release with no pre-release follows its
        // pre-releases; post-releases follow; a dev release precedes the
        // release it develops; a local version follows its public one.
        fn pre_key(version: &Version) -> (i8, u8, u64) {
            match (version.pre, version.post, version.dev) {
                (None, None, Some(_)) => (-1, 0, 0),
                (Some((kind, number)), _, _) => (0, kind, number),
                (None, _, _) => (1, 0, 0),
            }
        }
        fn post_key(version: &Version) -> (i8, u64) {
            version.post.map_or((-1, 0), |post| (0, post))
        }
        fn dev_key(version: &Version) -> (i8, u64) {
            version.dev.map_or((1, 0), |dev| (0, dev))
        }
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| self.compare_release(other))
            .then_with(|| pre_key(self).cmp(&pre_key(other)))
            .then_with(|| post_key(self).cmp(&post_key(other)))
            .then_with(|| dev_key(self).cmp(&dev_key(other)))
            .then_with(|| self.local.cmp(&other.local))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}!", self.epoch)?;
        }
        let release: Vec<String> = self.release.iter().map(u64::to_string).collect();
        write!(f, "{}", release.join("."))?;
        if let Some((kind, number)) = self.pre {
            write!(f, "{}{number}", ["a", "b", "rc"][usize::from(kind)])?;
        }
        if let Some(post) = self.post {
            write!(f, ".post{post}")?;
        }
        if let Some(dev) = self.dev {
            write!(f, ".dev{dev}")?;
        }
        if !self.local.is_empty() {
            let local: Vec<String> = self
                .local
                .iter()
                .map(|part| match part {
                    LocalPart::Number(number) => number.to_string(),
                    LocalPart::Text(text) => text.clone(),
                })
                .collect();
            write!(f, "+{}", local.join("."))?;
        }
        Ok(())
    }
}

/// Whether two version strings name the same PEP 440 version (`1.0` and
/// `1.0.0` do). Unparsable strings are compared as text.
pub fn same_version(a: &str, b: &str) -> bool {
    match (Version::parse(a), Version::parse(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a.trim() == b.trim(),
    }
}

/// One PEP 440 comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Compatible,
    Equal,
    NotEqual,
    LessEqual,
    GreaterEqual,
    Less,
    Greater,
    Arbitrary,
}

/// One clause of a specifier set: `>=3.10`, `==3.11.*`.
#[derive(Debug, Clone)]
struct Specifier {
    operator: Operator,
    /// The version text as written, for `===` and wildcards.
    text: String,
    wildcard: bool,
    version: Option<Version>,
}

impl Specifier {
    fn parse(text: &str) -> Option<Specifier> {
        let text = text.trim();
        let (operator, rest) = [
            ("===", Operator::Arbitrary),
            ("~=", Operator::Compatible),
            ("==", Operator::Equal),
            ("!=", Operator::NotEqual),
            ("<=", Operator::LessEqual),
            (">=", Operator::GreaterEqual),
            ("<", Operator::Less),
            (">", Operator::Greater),
        ]
        .into_iter()
        .find_map(|(symbol, operator)| text.strip_prefix(symbol).map(|rest| (operator, rest)))?;
        let rest = rest.trim();
        let (body, wildcard) = match rest.strip_suffix(".*") {
            Some(body) if matches!(operator, Operator::Equal | Operator::NotEqual) => (body, true),
            _ => (rest, false),
        };
        let version = Version::parse(body);
        if version.is_none() && operator != Operator::Arbitrary {
            return None;
        }
        Some(Specifier {
            operator,
            text: rest.to_string(),
            wildcard,
            version,
        })
    }

    fn contains(&self, candidate: &Version, candidate_text: &str) -> bool {
        let Some(spec) = &self.version else {
            return candidate_text.trim().eq_ignore_ascii_case(&self.text);
        };
        match self.operator {
            Operator::Arbitrary => candidate_text.trim().eq_ignore_ascii_case(&self.text),
            Operator::Equal if self.wildcard => prefix_matches(candidate, spec),
            Operator::NotEqual if self.wildcard => !prefix_matches(candidate, spec),
            Operator::Equal => {
                if spec.local.is_empty() {
                    candidate.public() == *spec
                } else {
                    candidate == spec
                }
            }
            Operator::NotEqual => {
                if spec.local.is_empty() {
                    candidate.public() != *spec
                } else {
                    candidate != spec
                }
            }
            Operator::LessEqual => candidate.public() <= *spec,
            Operator::GreaterEqual => candidate.public() >= *spec,
            // `<V` excludes pre-releases of V, and `>V` post-releases of V,
            // unless V is one itself.
            Operator::Less => {
                candidate.public() < *spec
                    && !(candidate.is_prerelease()
                        && !spec.is_prerelease()
                        && candidate.compare_release(spec) == Ordering::Equal)
            }
            Operator::Greater => {
                candidate.public() > *spec
                    && !(candidate.post.is_some()
                        && spec.post.is_none()
                        && candidate.compare_release(spec) == Ordering::Equal)
            }
            Operator::Compatible => {
                let length = spec.release.len();
                if length < 2 {
                    return false;
                }
                let prefix = Version {
                    epoch: spec.epoch,
                    release: spec.release[..length - 1].to_vec(),
                    pre: None,
                    post: None,
                    dev: None,
                    local: Vec::new(),
                };
                candidate.public() >= *spec && prefix_matches(candidate, &prefix)
            }
        }
    }
}

/// Whether `candidate`'s release starts with `prefix`'s, padding the
/// candidate with zeros: `3.11.4` matches `3.11`, and `3` matches `3.0`.
fn prefix_matches(candidate: &Version, prefix: &Version) -> bool {
    candidate.epoch == prefix.epoch
        && (0..prefix.release.len())
            .all(|index| candidate.release_at(index) == prefix.release_at(index))
}

/// A PEP 440 specifier set, such as a `requires-python` value.
#[derive(Debug, Clone)]
pub struct SpecifierSet {
    specifiers: Vec<Specifier>,
}

impl SpecifierSet {
    /// Parse a comma-separated set. An empty set, or `*`, admits everything.
    pub fn parse(text: &str) -> Option<SpecifierSet> {
        let text = text.trim();
        if text.is_empty() || text == "*" {
            return Some(SpecifierSet {
                specifiers: Vec::new(),
            });
        }
        text.split(',')
            .map(Specifier::parse)
            .collect::<Option<Vec<_>>>()
            .map(|specifiers| SpecifierSet { specifiers })
    }

    /// Whether `version` satisfies every clause.
    pub fn contains(&self, version: &str) -> bool {
        let Some(parsed) = Version::parse(version) else {
            return false;
        };
        self.specifiers
            .iter()
            .all(|specifier| specifier.contains(&parsed, version))
    }
}

/// The values environment markers are evaluated against: one target Python
/// on one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerEnvironment {
    pub python_version: String,
    pub python_full_version: String,
    pub os_name: String,
    pub sys_platform: String,
    pub platform_system: String,
    pub platform_machine: String,
    pub platform_release: String,
    pub platform_version: String,
    pub implementation_name: String,
    pub platform_python_implementation: String,
    /// Whether every extra and dependency group counts as requested, which is
    /// how an analysis environment loads a project: all of its code, and
    /// everything any of it imports.
    pub all_extras: bool,
}

impl MarkerEnvironment {
    /// CPython `full_version` on the platform named by Rust's target `os` and
    /// `arch` (`std::env::consts` spelling).
    pub fn cpython(full_version: &str, os: &str, arch: &str) -> Self {
        let release: Vec<&str> = full_version.split('.').collect();
        let python_version = release
            .get(..2)
            .map_or_else(|| full_version.to_string(), |parts| parts.join("."));
        let (os_name, sys_platform, platform_system) = match os {
            "macos" => ("posix", "darwin", "Darwin"),
            "windows" => ("nt", "win32", "Windows"),
            "linux" => ("posix", "linux", "Linux"),
            other => ("posix", other, other),
        };
        let platform_machine = match (os, arch) {
            ("macos", "aarch64") => "arm64",
            ("windows", "x86_64") => "AMD64",
            ("windows", "aarch64") => "ARM64",
            (_, arch) => arch,
        };
        Self {
            python_version,
            python_full_version: full_version.to_string(),
            os_name: os_name.to_string(),
            sys_platform: sys_platform.to_string(),
            platform_system: platform_system.to_string(),
            platform_machine: platform_machine.to_string(),
            platform_release: String::new(),
            platform_version: String::new(),
            implementation_name: "cpython".to_string(),
            platform_python_implementation: "CPython".to_string(),
            all_extras: true,
        }
    }

    fn variable(&self, name: &str) -> Option<&str> {
        Some(match name {
            "python_version" => &self.python_version,
            "python_full_version" | "implementation_version" => &self.python_full_version,
            "os_name" | "os.name" => &self.os_name,
            "sys_platform" | "sys.platform" => &self.sys_platform,
            "platform_system" => &self.platform_system,
            "platform_machine" | "platform.machine" => &self.platform_machine,
            "platform_release" => &self.platform_release,
            "platform_version" | "platform.version" => &self.platform_version,
            "implementation_name" => &self.implementation_name,
            "platform_python_implementation"
            | "platform.python_implementation"
            | "python_implementation" => &self.platform_python_implementation,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Name(String),
    Text(String),
    Operator(String),
    Open,
    Close,
    And,
    Or,
}

fn tokenize(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if c.is_whitespace() {
            index += 1;
        } else if c == '(' {
            tokens.push(Token::Open);
            index += 1;
        } else if c == ')' {
            tokens.push(Token::Close);
            index += 1;
        } else if c == '\'' || c == '"' {
            let end = chars[index + 1..]
                .iter()
                .position(|&next| next == c)
                .ok_or_else(|| format!("an unterminated string in `{text}`"))?;
            tokens.push(Token::Text(
                chars[index + 1..index + 1 + end].iter().collect(),
            ));
            index += end + 2;
        } else if "<>=!~".contains(c) {
            let mut end = index;
            while end < chars.len() && "<>=!~".contains(chars[end]) {
                end += 1;
            }
            tokens.push(Token::Operator(chars[index..end].iter().collect()));
            index = end;
        } else if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            let mut end = index;
            while end < chars.len()
                && (chars[end].is_ascii_alphanumeric() || chars[end] == '_' || chars[end] == '.')
            {
                end += 1;
            }
            let word: String = chars[index..end].iter().collect();
            index = end;
            tokens.push(match word.as_str() {
                "and" => Token::And,
                "or" => Token::Or,
                "in" => Token::Operator("in".to_string()),
                "not" => {
                    // `not in` is one operator.
                    let rest: String = chars[index..].iter().collect();
                    let trimmed = rest.trim_start();
                    let Some(after) = trimmed.strip_prefix("in") else {
                        return Err(format!("`not` without `in` in `{text}`"));
                    };
                    if after.starts_with(|next: char| next.is_ascii_alphanumeric() || next == '_') {
                        return Err(format!("`not` without `in` in `{text}`"));
                    }
                    index += rest.len() - trimmed.len() + 2;
                    Token::Operator("not in".to_string())
                }
                _ => Token::Name(word),
            });
        } else {
            return Err(format!("an unexpected `{c}` in `{text}`"));
        }
    }
    Ok(tokens)
}

struct Evaluator<'a> {
    tokens: Vec<Token>,
    position: usize,
    environment: &'a MarkerEnvironment,
    text: &'a str,
}

impl Evaluator<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += 1;
        token
    }

    fn or(&mut self) -> Result<bool, String> {
        let mut value = self.and()?;
        while self.peek() == Some(&Token::Or) {
            self.position += 1;
            // Both sides are parsed, so an error on either is reported.
            let right = self.and()?;
            value = value || right;
        }
        Ok(value)
    }

    fn and(&mut self) -> Result<bool, String> {
        let mut value = self.atom()?;
        while self.peek() == Some(&Token::And) {
            self.position += 1;
            let right = self.atom()?;
            value = value && right;
        }
        Ok(value)
    }

    fn atom(&mut self) -> Result<bool, String> {
        if self.peek() == Some(&Token::Open) {
            self.position += 1;
            let value = self.or()?;
            if self.next() != Some(Token::Close) {
                return Err(format!("an unclosed `(` in `{}`", self.text));
            }
            return Ok(value);
        }
        let left = self.next();
        let Some(Token::Operator(operator)) = self.next() else {
            return Err(format!(
                "a comparison without an operator in `{}`",
                self.text
            ));
        };
        let right = self.next();
        self.compare(left, &operator, right)
    }

    fn compare(
        &self,
        left: Option<Token>,
        operator: &str,
        right: Option<Token>,
    ) -> Result<bool, String> {
        let text = self.text;
        let side_name = |token: &Option<Token>| match token {
            Some(Token::Name(name)) => Some(name.clone()),
            _ => None,
        };
        // Requested extras and dependency groups: `extra == "x"`, and PEP
        // 751's `"x" in extras` / `"x" in dependency_groups`.
        let set_variable = |name: &str| matches!(name, "extra" | "extras" | "dependency_groups");
        if let Some(name) = side_name(&left)
            .filter(|name| set_variable(name))
            .or_else(|| side_name(&right).filter(|name| set_variable(name)))
        {
            let requested = self.environment.all_extras;
            return Ok(match (name.as_str(), operator) {
                ("extra", "==") => requested,
                ("extra", "!=") => true,
                (_, "in") => requested,
                (_, "not in") => !requested,
                _ => {
                    return Err(format!(
                        "`{name} {operator}` is not a marker comparison in `{text}`"
                    ))
                }
            });
        }
        let value = |token: Option<Token>| -> Result<String, String> {
            match token {
                Some(Token::Text(text)) => Ok(text),
                Some(Token::Name(name)) => self
                    .environment
                    .variable(&name)
                    .map(str::to_string)
                    .ok_or_else(|| format!("an unknown marker variable `{name}` in `{text}`")),
                _ => Err(format!("a comparison without a value in `{text}`")),
            }
        };
        let (left, right) = (value(left)?, value(right)?);
        Ok(match operator {
            "in" => right.contains(&left),
            "not in" => !right.contains(&left),
            _ => {
                let version = Version::parse(&left);
                match (version, Specifier::parse(&format!("{operator}{right}"))) {
                    (Some(version), Some(specifier)) => specifier.contains(&version, &left),
                    _ => match operator {
                        "==" | "===" => left == right,
                        "!=" => left != right,
                        _ => false,
                    },
                }
            }
        })
    }
}

/// Evaluate one PEP 508 marker expression. An error names what could not be
/// read; callers decide whether an unreadable marker includes or excludes.
pub fn evaluate(marker: &str, environment: &MarkerEnvironment) -> Result<bool, String> {
    let marker = marker.trim();
    if marker.is_empty() {
        return Ok(true);
    }
    let mut evaluator = Evaluator {
        tokens: tokenize(marker)?,
        position: 0,
        environment,
        text: marker,
    };
    let value = evaluator.or()?;
    if evaluator.position != evaluator.tokens.len() {
        return Err(format!("trailing text in `{marker}`"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} parses"))
    }

    #[test]
    fn versions_order_as_pep_440_says() {
        let ordered = [
            "1.0.dev0",
            "1.0a1",
            "1.0a2.dev1",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0+local.7",
            "1.0.post1.dev0",
            "1.0.post1",
            "1.1.dev1",
            "1.1",
            "2!0.1",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(v("1.0"), v("1.0.0"));
        assert_eq!(v("1.0-1"), v("1.0.post1"));
        assert_eq!(v("1.0C1"), v("1.0rc1"));
        assert_eq!(v("v2.0_alpha.3").to_string(), "2.0a3");
        assert!(Version::parse("not-a-version").is_none());
        assert!(same_version("2.31", "2.31.0"));
    }

    #[test]
    fn specifier_sets_follow_pep_440() {
        let set = |text: &str| SpecifierSet::parse(text).unwrap();
        assert!(set(">=3.10").contains("3.11.16"));
        assert!(!set(">=3.10").contains("3.9.18"));
        assert!(set(">=3.8, !=3.9.*, <4").contains("3.10.1"));
        assert!(!set(">=3.8, !=3.9.*, <4").contains("3.9.2"));
        assert!(set("==3.11.*").contains("3.11.0"));
        assert!(set("~=3.10").contains("3.14.7"));
        assert!(!set("~=3.10.2").contains("3.11.0"));
        assert!(!set("<3.11").contains("3.11.0rc1"));
        assert!(set("*").contains("3.12.0"));
        assert!(set("").contains("3.12.0"));
        assert!(SpecifierSet::parse(">=banana").is_none());
    }

    #[test]
    fn markers_evaluate_for_the_target_not_the_host() {
        let env = MarkerEnvironment::cpython("3.11.16", "macos", "aarch64");
        let yes = |marker: &str| evaluate(marker, &env).unwrap();
        assert!(yes("python_full_version < '3.14'"));
        assert!(!yes("python_full_version >= '3.14'"));
        assert!(yes(
            "python_version < \"3.12\" and sys_platform == 'darwin'"
        ));
        assert!(!yes(
            "sys_platform == 'win32' or platform_system == 'Linux'"
        ));
        assert!(yes(
            "(os_name == 'nt' or os_name == 'posix') and platform_machine == 'arm64'"
        ));
        assert!(yes("'arm' in platform_machine"));
        assert!(yes("platform_python_implementation != 'PyPy'"));
        assert!(yes("'3.10' <= python_version"));
        assert!(yes(
            "implementation_name == 'cpython' and python_version >= '3'"
        ));

        let linux = MarkerEnvironment::cpython("3.14.7", "linux", "x86_64");
        assert!(evaluate(
            "platform_machine == 'x86_64' and python_version >= '3.14'",
            &linux
        )
        .unwrap());
    }

    /// An analysis environment requests every extra and dependency group.
    #[test]
    fn every_extra_and_group_counts_as_requested() {
        let mut env = MarkerEnvironment::cpython("3.12.14", "linux", "x86_64");
        assert!(evaluate("extra == 'socks'", &env).unwrap());
        assert!(evaluate("'dev' in dependency_groups", &env).unwrap());
        assert!(evaluate("'docs' in extras and python_version >= '3.10'", &env).unwrap());
        env.all_extras = false;
        assert!(!evaluate("extra == 'socks'", &env).unwrap());
        assert!(evaluate("'dev' not in dependency_groups", &env).unwrap());
    }

    #[test]
    fn malformed_markers_are_errors_not_guesses() {
        let env = MarkerEnvironment::cpython("3.12.14", "linux", "x86_64");
        for bad in [
            "python_version <",
            "(python_version < '3'",
            "shoe_size == '9'",
            "python_version < '3' xor",
        ] {
            assert!(evaluate(bad, &env).is_err(), "{bad}");
        }
        assert!(evaluate("", &env).unwrap());
    }
}
