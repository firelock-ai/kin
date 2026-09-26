// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Symbols outside the repository, named the way SCIP names them.
//!
//! An [`ExternalSymbol`] is a typed view of an [`ExternalReference`] in the
//! `kin-scip-v1` namespace. Its `canonical_source` is a SCIP package, the
//! manager, name and version (`npm typescript 5.6.3`), and its `symbol` is a
//! SCIP descriptor chain (`` `lib.es5.d.ts`/Array#map(). ``). The same symbol
//! at the same version is one identity in every repository; the same symbol
//! at another version is another identity, on purpose.
//!
//! A standard library is named by the version the resolver actually loaded:
//! the TypeScript package whose lib files the server read, `@types/node`, the
//! Python version pyright evaluated its stubs for, the Rust sysroot's rustc, or
//! the Go toolchain. [`ExternalSymbol::is_stdlib`] is a fixed table over the
//! package and never part of the identity.

use std::fmt;

use crate::external_reference::ExternalReference;
use crate::{ModelError, Result};

/// The resolution namespace every external symbol is recorded under.
pub const EXTERNAL_SYMBOL_NAMESPACE: &str = "kin-scip-v1";

/// The package a symbol belongs to: `manager name version`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScipPackage {
    /// `npm`, `python`, `cargo`, `go`.
    pub manager: String,
    /// The package's own name: `typescript`, `@types/node`, `python-stdlib`,
    /// `std`, `github.com/gin-gonic/gin`.
    pub name: String,
    /// The version the resolver loaded.
    pub version: String,
}

impl ScipPackage {
    pub fn new(
        manager: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self> {
        let package = Self {
            manager: manager.into(),
            name: name.into(),
            version: version.into(),
        };
        for (label, value) in [
            ("manager", &package.manager),
            ("name", &package.name),
            ("version", &package.version),
        ] {
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                return Err(ModelError::InvalidOperation(format!(
                    "external symbol package {label} {value:?} must be non-empty, trimmed text"
                )));
            }
        }
        if package.manager.contains(' ') {
            return Err(ModelError::InvalidOperation(format!(
                "external symbol package manager {:?} must not contain a space",
                package.manager
            )));
        }
        Ok(package)
    }

    /// The SCIP spelling: the three fields separated by one space, a space
    /// inside a field written as two.
    pub fn encode(&self) -> String {
        [&self.manager, &self.name, &self.version]
            .iter()
            .map(|field| field.replace(' ', "  "))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Read the SCIP spelling back.
    pub fn decode(text: &str) -> Result<Self> {
        let mut fields = Vec::with_capacity(3);
        let mut current = String::new();
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == ' ' {
                if chars.peek() == Some(&' ') {
                    chars.next();
                    current.push(' ');
                } else {
                    fields.push(std::mem::take(&mut current));
                }
            } else {
                current.push(ch);
            }
        }
        fields.push(current);
        let [manager, name, version]: [String; 3] = fields.try_into().map_err(|_| {
            ModelError::InvalidOperation(format!(
                "external symbol package {text:?} is not `manager name version`"
            ))
        })?;
        Self::new(manager, name, version)
    }
}

impl fmt::Display for ScipPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encode())
    }
}

/// What one descriptor names, as its SCIP suffix spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DescriptorSuffix {
    /// `name/`: a module, namespace, package or file.
    Namespace,
    /// `name#`: a class, interface, struct, enum or trait.
    Type,
    /// `name.`: a value: a field, property, constant or variable.
    Term,
    /// `name(disambiguator).`: a function or method.
    Method,
    /// `[name]`.
    TypeParameter,
    /// `(name)`.
    Parameter,
    /// `name:`.
    Meta,
    /// `name!`.
    Macro,
}

/// One step of a descriptor chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScipDescriptor {
    pub name: String,
    pub suffix: DescriptorSuffix,
    /// Tells overloads of one method apart. Empty for every other suffix and
    /// usually for a method too.
    pub disambiguator: String,
}

impl ScipDescriptor {
    pub fn new(name: impl Into<String>, suffix: DescriptorSuffix) -> Self {
        Self {
            name: name.into(),
            suffix,
            disambiguator: String::new(),
        }
    }

    pub fn namespace(name: impl Into<String>) -> Self {
        Self::new(name, DescriptorSuffix::Namespace)
    }

    pub fn type_(name: impl Into<String>) -> Self {
        Self::new(name, DescriptorSuffix::Type)
    }

    pub fn term(name: impl Into<String>) -> Self {
        Self::new(name, DescriptorSuffix::Term)
    }

    pub fn method(name: impl Into<String>) -> Self {
        Self::new(name, DescriptorSuffix::Method)
    }

    fn encode_into(&self, out: &mut String) {
        match self.suffix {
            DescriptorSuffix::Namespace => {
                push_name(out, &self.name);
                out.push('/');
            }
            DescriptorSuffix::Type => {
                push_name(out, &self.name);
                out.push('#');
            }
            DescriptorSuffix::Term => {
                push_name(out, &self.name);
                out.push('.');
            }
            DescriptorSuffix::Method => {
                push_name(out, &self.name);
                out.push('(');
                push_name_bare(out, &self.disambiguator);
                out.push_str(").");
            }
            DescriptorSuffix::TypeParameter => {
                out.push('[');
                push_name(out, &self.name);
                out.push(']');
            }
            DescriptorSuffix::Parameter => {
                out.push('(');
                push_name(out, &self.name);
                out.push(')');
            }
            DescriptorSuffix::Meta => {
                push_name(out, &self.name);
                out.push(':');
            }
            DescriptorSuffix::Macro => {
                push_name(out, &self.name);
                out.push('!');
            }
        }
    }
}

/// Whether SCIP writes `name` without backticks.
fn is_simple_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '+' | '-' | '$'))
}

fn push_name(out: &mut String, name: &str) {
    if is_simple_identifier(name) {
        out.push_str(name);
    } else {
        out.push('`');
        out.push_str(&name.replace('`', "``"));
        out.push('`');
    }
}

fn push_name_bare(out: &mut String, name: &str) {
    if name.is_empty() {
        return;
    }
    push_name(out, name);
}

/// A symbol outside the repository: its package and its descriptor chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExternalSymbol {
    pub package: ScipPackage,
    pub descriptors: Vec<ScipDescriptor>,
}

impl ExternalSymbol {
    pub fn new(package: ScipPackage, descriptors: Vec<ScipDescriptor>) -> Result<Self> {
        if descriptors.is_empty() {
            return Err(ModelError::InvalidOperation(
                "an external symbol needs at least one descriptor".to_string(),
            ));
        }
        if descriptors.iter().any(|descriptor| {
            descriptor.name.is_empty() || descriptor.name.chars().any(char::is_control)
        }) {
            return Err(ModelError::InvalidOperation(
                "external symbol descriptors must be named without control characters".to_string(),
            ));
        }
        Ok(Self {
            package,
            descriptors,
        })
    }

    /// The descriptor chain in SCIP's spelling.
    pub fn encode_descriptors(&self) -> String {
        let mut out = String::new();
        for descriptor in &self.descriptors {
            descriptor.encode_into(&mut out);
        }
        out
    }

    /// The graph node this symbol is recorded as.
    pub fn to_reference(&self) -> Result<ExternalReference> {
        ExternalReference::new_resolved(
            EXTERNAL_SYMBOL_NAMESPACE,
            self.package.encode(),
            self.encode_descriptors(),
        )
    }

    /// The typed view of a reference recorded in the `kin-scip-v1` namespace,
    /// or `None` for any other namespace or a coordinate that does not parse.
    pub fn from_reference(reference: &ExternalReference) -> Option<Self> {
        if reference.resolution_namespace != EXTERNAL_SYMBOL_NAMESPACE {
            return None;
        }
        let package = ScipPackage::decode(&reference.canonical_source).ok()?;
        let descriptors = decode_descriptors(&reference.symbol).ok()?;
        Self::new(package, descriptors).ok()
    }

    /// Whether the package is a language's standard library, by a fixed table
    /// over the manager and name.
    pub fn is_stdlib(&self) -> bool {
        is_stdlib_package(&self.package)
    }

    /// The symbol as a reader would spell it: its type and member names joined
    /// by dots (`Array.map`), or its last namespace when it names only a
    /// module.
    pub fn display_name(&self) -> String {
        let named: Vec<&str> = self
            .descriptors
            .iter()
            .filter(|descriptor| {
                matches!(
                    descriptor.suffix,
                    DescriptorSuffix::Type
                        | DescriptorSuffix::Term
                        | DescriptorSuffix::Method
                        | DescriptorSuffix::Macro
                )
            })
            .map(|descriptor| descriptor.name.as_str())
            .collect();
        if named.is_empty() {
            return self
                .descriptors
                .last()
                .map(|descriptor| descriptor.name.clone())
                .unwrap_or_default();
        }
        named.join(".")
    }
}

/// Whether `package` is a language's standard library.
pub fn is_stdlib_package(package: &ScipPackage) -> bool {
    matches!(
        (package.manager.as_str(), package.name.as_str()),
        ("npm", "typescript")
            | ("npm", "@types/node")
            | ("python", "python-stdlib")
            | ("cargo", "std" | "core" | "alloc" | "proc_macro" | "test")
            | ("go", "std")
    )
}

/// Read a SCIP descriptor chain.
pub fn decode_descriptors(text: &str) -> Result<Vec<ScipDescriptor>> {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0usize;
    let mut descriptors = Vec::new();
    let fail = || ModelError::InvalidOperation(format!("{text:?} is not a SCIP descriptor chain"));
    let read_name = |at: &mut usize| -> Result<String> {
        if chars.get(*at) == Some(&'`') {
            *at += 1;
            let mut name = String::new();
            loop {
                match chars.get(*at) {
                    None => return Err(fail()),
                    Some('`') if chars.get(*at + 1) == Some(&'`') => {
                        name.push('`');
                        *at += 2;
                    }
                    Some('`') => {
                        *at += 1;
                        return Ok(name);
                    }
                    Some(ch) => {
                        name.push(*ch);
                        *at += 1;
                    }
                }
            }
        }
        let start = *at;
        while chars
            .get(*at)
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '+' | '-' | '$'))
        {
            *at += 1;
        }
        Ok(chars[start..*at].iter().collect())
    };
    while at < chars.len() {
        match chars[at] {
            '[' => {
                at += 1;
                let name = read_name(&mut at)?;
                if chars.get(at) != Some(&']') || name.is_empty() {
                    return Err(fail());
                }
                at += 1;
                descriptors.push(ScipDescriptor::new(name, DescriptorSuffix::TypeParameter));
            }
            '(' => {
                at += 1;
                let name = read_name(&mut at)?;
                if chars.get(at) != Some(&')') || name.is_empty() {
                    return Err(fail());
                }
                at += 1;
                descriptors.push(ScipDescriptor::new(name, DescriptorSuffix::Parameter));
            }
            _ => {
                let name = read_name(&mut at)?;
                if name.is_empty() {
                    return Err(fail());
                }
                let descriptor = match chars.get(at) {
                    Some('/') => ScipDescriptor::new(name, DescriptorSuffix::Namespace),
                    Some('#') => ScipDescriptor::new(name, DescriptorSuffix::Type),
                    Some('.') => ScipDescriptor::new(name, DescriptorSuffix::Term),
                    Some(':') => ScipDescriptor::new(name, DescriptorSuffix::Meta),
                    Some('!') => ScipDescriptor::new(name, DescriptorSuffix::Macro),
                    Some('(') => {
                        at += 1;
                        let disambiguator = if chars.get(at) == Some(&')') {
                            String::new()
                        } else {
                            read_name(&mut at)?
                        };
                        if chars.get(at) != Some(&')') || chars.get(at + 1) != Some(&'.') {
                            return Err(fail());
                        }
                        at += 1;
                        ScipDescriptor {
                            name,
                            suffix: DescriptorSuffix::Method,
                            disambiguator,
                        }
                    }
                    _ => return Err(fail()),
                };
                at += 1;
                descriptors.push(descriptor);
            }
        }
    }
    Ok(descriptors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array_map(version: &str) -> ExternalSymbol {
        ExternalSymbol::new(
            ScipPackage::new("npm", "typescript", version).unwrap(),
            vec![
                ScipDescriptor::namespace("lib.es5.d.ts"),
                ScipDescriptor::type_("Array"),
                ScipDescriptor::method("map"),
            ],
        )
        .unwrap()
    }

    #[test]
    fn array_map_has_a_pinned_coordinate_and_identity() {
        let symbol = array_map("5.6.3");
        let reference = symbol.to_reference().unwrap();
        assert_eq!(reference.resolution_namespace, "kin-scip-v1");
        assert_eq!(reference.canonical_source, "npm typescript 5.6.3");
        assert_eq!(reference.symbol, "`lib.es5.d.ts`/Array#map().");
        assert_eq!(
            reference.id.to_string(),
            "cdfea2c4-76bd-50a9-b128-b1ffb51fe549"
        );
        assert_eq!(
            ExternalSymbol::from_reference(&reference),
            Some(symbol.clone())
        );
        assert!(symbol.is_stdlib());
        assert_eq!(symbol.display_name(), "Array.map");
        // One TypeScript version, one identity, whichever repository asks.
        assert_eq!(array_map("5.6.3").to_reference().unwrap().id, reference.id);
        assert_ne!(
            array_map("5.7.2").to_reference().unwrap().id,
            reference.id,
            "another version is another symbol, on purpose"
        );
    }

    #[test]
    fn descriptor_chains_round_trip_every_suffix_and_escape() {
        let descriptors = vec![
            ScipDescriptor::namespace("net/http"),
            ScipDescriptor::type_("Client"),
            ScipDescriptor {
                name: "Do".to_string(),
                suffix: DescriptorSuffix::Method,
                disambiguator: "+1".to_string(),
            },
            ScipDescriptor::new("T", DescriptorSuffix::TypeParameter),
            ScipDescriptor::new("req", DescriptorSuffix::Parameter),
            ScipDescriptor::new("odd`name", DescriptorSuffix::Term),
            ScipDescriptor::new("meta", DescriptorSuffix::Meta),
            ScipDescriptor::new("vec", DescriptorSuffix::Macro),
        ];
        let symbol = ExternalSymbol::new(
            ScipPackage::new("go", "std", "1.23.4").unwrap(),
            descriptors.clone(),
        )
        .unwrap();
        let encoded = symbol.encode_descriptors();
        assert_eq!(
            encoded,
            "`net/http`/Client#Do(+1).[T](req)`odd``name`.meta:vec!"
        );
        assert_eq!(decode_descriptors(&encoded).unwrap(), descriptors);
        assert!(decode_descriptors("Array#map(").is_err());
        assert!(decode_descriptors("`unterminated/").is_err());
    }

    #[test]
    fn packages_escape_spaces_and_refuse_malformed_text() {
        let package = ScipPackage::new("npm", "odd name", "1.0.0").unwrap();
        assert_eq!(package.encode(), "npm odd  name 1.0.0");
        assert_eq!(ScipPackage::decode(&package.encode()).unwrap(), package);
        assert!(ScipPackage::decode("npm typescript").is_err());
        assert!(ScipPackage::new("np m", "x", "1").is_err());
        assert!(ScipPackage::new("npm", "", "1").is_err());
    }

    #[test]
    fn the_standard_library_table_reads_the_package_only() {
        for (manager, name, stdlib) in [
            ("npm", "typescript", true),
            ("npm", "@types/node", true),
            ("npm", "lodash", false),
            ("python", "python-stdlib", true),
            ("python", "requests", false),
            ("cargo", "core", true),
            ("cargo", "serde", false),
            ("go", "std", true),
            ("go", "github.com/gin-gonic/gin", false),
        ] {
            let package = ScipPackage::new(manager, name, "1").unwrap();
            assert_eq!(is_stdlib_package(&package), stdlib, "{manager} {name}");
        }
        let other = ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        assert_eq!(ExternalSymbol::from_reference(&other), None);
    }
}
