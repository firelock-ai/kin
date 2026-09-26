// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_parser::{FilePathId, JavaScriptAdapter, LanguageAdapter, ParseOutput};

fn parse(source: &str) -> ParseOutput {
    let adapter = JavaScriptAdapter;
    let tree = adapter.parse(source.as_bytes()).unwrap();
    adapter
        .extract(&tree, source.as_bytes(), &FilePathId::new("src/service.js"))
        .unwrap()
}

fn fixture(owner: &str, property: &str, constructor: &str, module: &str, member: &str) -> String {
    format!(
        "var {constructor} = require('{module}');\n\
         var {owner} = {{}};\n\
         {owner}.initialize = function() {{\n\
           var held = null;\n\
           Object.defineProperty(this, '{property}', {{\n\
             configurable: true, enumerable: true,\n\
             get: function() {{\n\
               if (held === null) {{ held = new {constructor}({{ strict: this.enabled() }}); }}\n\
               return held;\n\
             }}\n\
           }});\n\
         }};\n\
         {owner}.dispatch = function(request) {{ this.{property}.{member}(request); }};\n"
    )
}

#[test]
fn lazy_getter_imported_receiver_is_structural_and_keeps_the_call_site() {
    for (owner, property, constructor, module, member) in [
        ("app", "router", "Router", "router", "handle"),
        ("service", "transport", "Channel", "sample-channel", "send"),
        ("container", "storage", "Backend", "@example/store", "save"),
    ] {
        let source = fixture(owner, property, constructor, module, member);
        let output = parse(&source);
        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.src_name == format!("{owner}.dispatch"))
            .collect();
        assert_eq!(calls.len(), 1);
        let call = calls[0];
        assert_eq!(call.import_source.as_deref(), Some(module), "{call:?}");
        assert_eq!(call.dst_name, format!("{property}.{member}"));
        assert_eq!(
            call.receiver.as_deref(),
            Some(format!("this.{property}").as_str())
        );
        let site = call.site.as_ref().unwrap();
        assert_eq!(
            &source[site.start_byte..site.end_byte],
            format!("this.{property}.{member}(request)")
        );
        assert!(site.syntactic_role.is_some());
        assert!(
            output
                .entities
                .iter()
                .all(|e| e.name != format!("{owner}.{property}")),
            "a receiver provenance proof must not fabricate an independently editable member"
        );
    }
}

#[test]
fn lazy_getter_imported_receiver_refuses_disproved_or_unbound_chains() {
    let base = fixture("service", "transport", "Channel", "sample-channel", "send");
    let cases = [
        base.replace("sample-channel", "./channel"),
        base.replace("sample-channel", "../channel"),
        base.replace("sample-channel", "/channel"),
        base.replace("sample-channel", "C:/channel"),
        base.replace("sample-channel", "file:channel"),
        base.replace("sample-channel", "node:channel"),
        base.replace("return held;", "return replacement;"),
        base.replace("get: function()", "get: async function()"),
        base.replace("var held = null;", "const held = null;"),
        format!("{base}\nservice = other;"),
        format!("{base}\n[service] = replacements;"),
        format!("{base}\n({{service}} = replacements);"),
        format!("{base}\nfor (service of replacements) {{}}"),
        format!("{base}\nvar service = other;"),
        format!("{base}\nservice.dispatch = function(request) {{ this.transport.send(request); }};"),
        format!("{base}\nObject.defineProperty(service, 'transport', {{ value: other }});"),
        format!("{base}\nservice.override = function() {{ if (ready) Object.defineProperty(this, 'transport', {{ value: other }}); }};"),
        format!("{base}\nservice.override = function() {{ Object.assign(this, {{transport: other}}); }};"),
        format!("{base}\nservice.override = function() {{ Reflect.set(this, 'transport', other); }};"),
        format!("{base}\nservice.override = function() {{ ({{target: this.transport}} = source); }};"),
        format!("{base}\nservice.override = function() {{ Object.defineProperty(this, key, {{ value: other }}); }};"),
        base.replace("new Channel(", "new Alternate("),
        base.replace("return held;", "held = replacement; return held;"),
        base.replace("return held;", "escape(held); return held;"),
        base.replace("return held;", "escape({held}); return held;"),
        base.replace("function() {\nvar held", "function(Channel) {\nvar held"),
        base.replace("var held = null;", "var held = null; var Channel = Other;"),
        base.replace("var held = null;", "var held = null; const Object = Other;"),
        base.replace("return held;", "if (something) return other; return held;"),
        base.replace("held === null", "ready"),
        base.replace("var held = null;", "var held = makeInitial();"),
        base.replace(
            "this.transport.send(request);",
            "function nested() { this.transport.send(request); }",
        ),
        format!("{base}\nChannel = Other;"),
        format!("{base}\nservice.transport = other;"),
        format!("{base}\nservice.replace = function() {{ this.transport = other; }};"),
        format!("{base}\nservice.replace = function() {{ this['transport'] = other; }};"),
        format!("{base}\neval('Channel = Other');"),
        format!("{base}\nconst require = other;"),
        base.replace("get: function() {", "get: function(held) {"),
        base.replace("return held;", "try {} catch (held) {} return held;"),
        base.replace("var held = null;", "var held = null; var held = other;"),
    ];
    for (index, source) in cases.iter().enumerate() {
        assert_ne!(
            source, &base,
            "negative fixture {index} did not alter source"
        );
        let output = parse(source);
        assert!(
            output
                .relations
                .iter()
                .filter(|r| r.src_name == "service.dispatch")
                .all(|r| r.import_source.is_none()),
            "case {index}: {source}\n{:?}",
            output.relations
        );
    }
}

#[test]
fn lazy_getter_refuses_unknown_computed_writes() {
    let base = fixture("service", "transport", "Channel", "sample-channel", "send");
    let mut admitted = Vec::new();
    for receiver in ["this", "service"] {
        for write in [
            format!("{receiver}[key] = other;"),
            format!("{receiver}[key]++;"),
            format!("delete {receiver}[key];"),
            format!("[ {receiver}[key] ] = values;"),
            format!("({{ value: {receiver}[key] }} = values);"),
            format!("for ({receiver}[key] of values) {{}}"),
        ] {
            let source = format!("{base}\nservice.override = function(key) {{ {write} }};");
            if parse(&source)
                .relations
                .iter()
                .any(|r| r.src_name == "service.dispatch" && r.import_source.is_some())
            {
                admitted.push(write);
            }
        }
    }
    let registration = format!("{base}\nvar names = require('./names'); names.forEach(function(name) {{ service[name] = function() {{}}; }});");
    if parse(&registration)
        .relations
        .iter()
        .any(|r| r.src_name == "service.dispatch" && r.import_source.is_some())
    {
        admitted.push("dependency-driven owner method registration".to_owned());
    }
    for receiver in ["this", "service"] {
        let source =
            format!("{base}\nservice.override = function() {{ {receiver}['other'] = value; }};");
        assert!(
            parse(&source)
                .relations
                .iter()
                .any(|r| r.src_name == "service.dispatch"
                    && r.import_source.as_deref() == Some("sample-channel")),
            "a literal unrelated property is not a receiver overwrite"
        );
    }
    assert!(
        admitted.is_empty(),
        "unknown writes incorrectly retained imported receiver inference: {admitted:?}"
    );
}

#[test]
fn lazy_getter_refuses_owner_alias_redefinition_without_computed_write() {
    let base = fixture("service", "transport", "Channel", "sample-channel", "send");
    let cases = [
        ("direct", "const alias = service; Object.defineProperty(alias, 'transport', {value: {send() { return 'local'; }}});"),
        ("parenthesized", "const alias = (service); Object.defineProperty((alias), 'transport', {value: {send() { return 'local'; }}});"),
        ("chained_assignment", "let first; const second = first = service; Object.defineProperty(second, 'transport', {value: {send() { return 'local'; }}});"),
        ("lexical_this", "service.override = function() { const alias = this; Object.defineProperty(alias, 'transport', {value: {send() { return 'local'; }}}); }; service.override();"),
        ("computed_alias_write", "const alias = service; Reflect.deleteProperty(alias, 'transport'); (alias)[key] = {send() { return 'local'; }};"),
        ("transitive", "const first = service; const second = first; Object.defineProperty(second, 'transport', {value: {send() { return 'local'; }}});"),
        ("assignment", "let alias; alias = service; Object.defineProperty(alias, 'transport', {value: {send() { return 'local'; }}});"),
        ("reflect_definition", "const alias = service; Reflect.defineProperty(alias, 'transport', {value: {send() { return 'local'; }}});"),
        ("delete_and_write", "const alias = service; Reflect.deleteProperty(alias, 'transport'); alias.transport = {send() { return 'local'; }};"),
        ("define_properties", "const alias = service; Object.defineProperties(alias, {transport: {value: {send() { return 'local'; }}}});"),
        ("conditional_reassignment", "let alias = service; if (unrelated) alias = other; Object.defineProperty(alias, 'transport', {value: {send() { return 'local'; }}});"),
    ];
    let mut admitted = Vec::new();
    for (name, mutation) in cases {
        let source = format!("{base}\nservice.initialize(); {mutation} service.dispatch();\n");
        if parse(&source).relations.iter().any(|relation| {
            relation.src_name == "service.dispatch" && relation.import_source.is_some()
        }) {
            admitted.push(name);
        }
    }
    assert!(
        admitted.is_empty(),
        "owner alias replacements retained imported receiver inference: {admitted:?}"
    );
}

#[test]
fn lazy_getter_keeps_unrelated_owner_and_copy_mutations() {
    let base = fixture("service", "transport", "Channel", "sample-channel", "send");
    for tail in [
        "const other = {}; const alias = other; Object.defineProperty(alias, 'transport', {value: replacement});",
        "const copy = {...service}; Object.defineProperty(copy, 'transport', {value: replacement});",
        "const alias = service; alias.unrelated = replacement;",
        "const alias = service; Object.defineProperty(alias, 'unrelated', {value: replacement});",
    ] {
        let source = format!("{base}\n{tail}\n");
        assert!(parse(&source).relations.iter().any(|relation| {
            relation.src_name == "service.dispatch" && relation.import_source.as_deref() == Some("sample-channel")
        }), "unrelated mutation removed the original handoff: {tail}");
    }
}
