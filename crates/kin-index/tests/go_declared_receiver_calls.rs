// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{
    link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker, IndexPipeline,
    RelationResolution,
};
use kin_model::{
    ArtifactId, Entity, EntityId, EntityKind, FilePathId, Relation, RelationEvidence, RelationKind,
};
use kin_parser::{attach_go_package_metadata, GoAdapter, LanguageAdapter};

fn parse(path: &str, source: &str) -> FileParseData {
    let adapter = GoAdapter;
    let file_id = FilePathId::new(path);
    let tree = adapter.parse(source.as_bytes()).unwrap();
    let output = adapter.extract(&tree, source.as_bytes(), &file_id).unwrap();
    let mut entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|entity| {
            entity.into_entity_with_source(adapter.language_id(), &file_id, Some(source.as_bytes()))
        })
        .collect();
    attach_go_package_metadata(&tree, source.as_bytes(), &mut entities);
    FileParseData {
        file_path: path.into(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn entity(file: &FileParseData, name: &str) -> EntityId {
    file.entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap()
        .id
}

fn call_targets(relations: &[Relation], caller: EntityId) -> Vec<EntityId> {
    let mut targets: Vec<_> = relations
        .iter()
        .filter(|relation| {
            relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(caller)
        })
        .filter_map(|relation| relation.dst.as_entity())
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

/// The call sites `edge` carries, after checking its occurrence certificates.
///
/// A parser `Calls` edge carries, beside each site record, one span-free
/// certificate of the tier that site resolved at (`kin_index::occurrence`). A
/// certificate qualifies a site and is never one, so sites are read through
/// the product's own split rather than by counting raw evidence, and the
/// certificates are pinned here instead: one per site, of the current rule,
/// carrying none of a site's fields, valid for this edge, and certifying every
/// site at the edge's own tier.
fn certified_sites(edge: &Relation) -> Vec<&RelationEvidence> {
    let sites = kin_index::occurrence::original_evidence(edge)
        .unwrap_or_else(|| panic!("every occurrence certificate must validate: {edge:?}"));
    let certificates: Vec<_> = edge
        .evidence
        .iter()
        .filter(|record| kin_index::occurrence::is_certificate(record))
        .collect();
    assert_eq!(
        certificates.len(),
        sites.len(),
        "exactly one occurrence certificate per site: {edge:?}"
    );
    for certificate in certificates {
        assert_eq!(
            certificate.parser_rule.as_deref(),
            Some(kin_index::occurrence::OCCURRENCE_RULE)
        );
        assert!(certificate.source_span.is_none());
        assert!(certificate.source_path.is_none());
        assert!(certificate.resolved_path.is_none());
        assert!(certificate.call_shape.is_none());
        assert_eq!(certificate.occurrence_count, 0);
        assert!(certificate.token.is_some());
    }
    let (proven, withheld) = kin_index::occurrence::proven_sites(edge);
    assert!(!withheld, "no site may lose its certified tier: {edge:?}");
    assert_eq!(proven.len(), sites.len());
    assert!(
        kin_index::occurrence::groups(edge).iter().all(|group| {
            group.resolution == RelationResolution::of(edge)
                && !group.receiver_name_guess
                && !group.qualification_missing
        }),
        "every site is certified at the edge's own tier: {edge:?}"
    );
    sites
}

fn batch(files: &[FileParseData]) -> Vec<Relation> {
    let identities = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file(files, &identities).unwrap()
}

fn incremental(files: &[FileParseData]) -> IncrementalLinker {
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker
}

#[test]
fn same_file_receiver_calls_keep_each_site_and_do_not_capture_a_free_function() {
    let source = "package app\ntype App struct{}\nfunc (a *App) Run() { a.prepare(); a.prepare(); prepare() }\nfunc (a *App) prepare() {}\nfunc prepare() {}\n";
    let files = [parse("app.go", source)];
    let caller = entity(&files[0], "App.Run");
    let method = entity(&files[0], "App.prepare");
    let free = entity(&files[0], "prepare");
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        let mut expected = vec![method, free];
        expected.sort();
        assert_eq!(call_targets(&relations, caller), expected);
        let edge = relations
            .iter()
            .find(|r| {
                r.src.as_entity() == Some(caller)
                    && r.dst.as_entity() == Some(method)
                    && r.kind == RelationKind::Calls
            })
            .unwrap();
        assert_eq!(
            RelationResolution::of(edge),
            RelationResolution::TypeResolved
        );
        let sites = certified_sites(edge);
        assert_eq!(sites.len(), 2);
        assert!(sites.iter().all(|evidence| evidence.source_span.is_some()));
    }

    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("app.go"),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    assert!(indexed.entities.iter().all(|e| e
        .metadata
        .extra
        .get("go_package")
        .and_then(|v| v.as_str())
        == Some("app")));
    let method = indexed
        .entities
        .iter()
        .find(|e| e.name == "App.prepare")
        .unwrap()
        .id;
    let caller = indexed
        .entities
        .iter()
        .find(|e| e.name == "App.Run")
        .unwrap()
        .id;
    assert!(call_targets(&indexed.relations, caller).contains(&method));
}

fn package_fixture() -> Vec<FileParseData> {
    vec![
        parse("pkg/types.go", "package app\ntype App struct{}\n"),
        parse(
            "pkg/run.go",
            "package app\nfunc (a *App) Run() { a.prepare() }\n",
        ),
        parse(
            "pkg/prepare.go",
            "package app\nfunc (a *App) prepare() {}\n",
        ),
        parse(
            "other/app.go",
            "package app\ntype App struct{}\nfunc (a *App) prepare() {}\n",
        ),
        parse(
            "pkg/external_test.go",
            "package app_test\ntype App struct{}\nfunc (a *App) prepare() {}\n",
        ),
        parse(
            "pkg/other.go",
            "package app\ntype Other struct{}\nfunc (o *Other) prepare() {}\n",
        ),
    ]
}

#[test]
fn cross_file_dispatch_uses_package_and_receiver_through_incremental_checkpoint() {
    let files = package_fixture();
    let caller = entity(&files[1], "App.Run");
    let target = entity(&files[2], "App.prepare");
    let linker = incremental(&files);
    let encoded = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&encoded).unwrap()).unwrap();
    assert_eq!(
        encoded,
        serde_json::to_vec(&restored.to_checkpoint_v1()).unwrap()
    );
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files[1..2], &linker).unwrap(),
        link_cross_file_incremental(&files[1..2], &restored).unwrap(),
    ] {
        assert_eq!(call_targets(&relations, caller), vec![target]);
        let edge = relations
            .iter()
            .find(|r| r.src.as_entity() == Some(caller) && r.dst.as_entity() == Some(target))
            .unwrap();
        assert_eq!(
            RelationResolution::of(edge),
            RelationResolution::TypeResolved
        );
    }
}

#[test]
fn named_scalar_receiver_does_not_require_a_struct_entity() {
    let files = [
        parse(
            "pkg/app.go",
            "package app\ntype App string\nfunc (a App) Run() { a.prepare() }\n",
        ),
        parse("pkg/prepare.go", "package app\nfunc (a App) prepare() {}\n"),
    ];
    let caller = entity(&files[0], "App.Run");
    let target = entity(&files[1], "App.prepare");
    assert_eq!(
        files[0]
            .entities
            .iter()
            .find(|e| e.name == "App")
            .unwrap()
            .kind,
        EntityKind::TypeAlias
    );
    assert_eq!(call_targets(&batch(&files), caller), vec![target]);
}

#[test]
fn a_removed_method_never_rebinds_to_another_package() {
    let files = package_fixture();
    let caller = entity(&files[1], "App.Run");
    let mut linker = incremental(&files);
    linker.remove_file(&files[2].file_path);
    assert!(call_targets(
        &link_cross_file_incremental(&files[1..2], &linker).unwrap(),
        caller
    )
    .is_empty());
    let remaining: Vec<_> = files
        .into_iter()
        .enumerate()
        .filter_map(|(i, file)| (i != 2).then_some(file))
        .collect();
    assert!(call_targets(&batch(&remaining), caller).is_empty());
}

#[test]
fn missing_or_ambiguous_package_evidence_does_not_become_dispatch_proof() {
    let mut files = package_fixture();
    let caller = entity(&files[1], "App.Run");
    files[2].entities.iter_mut().for_each(|e| {
        e.metadata.extra.remove("go_package");
    });
    assert!(call_targets(&batch(&files), caller).is_empty());
    let mut files = package_fixture();
    files.push(parse(
        "pkg/duplicate.go",
        "package app\nfunc (a *App) prepare() {}\n",
    ));
    let caller = entity(&files[1], "App.Run");
    assert!(call_targets(&batch(&files), caller).is_empty());
}

#[test]
fn receiver_binding_respects_nested_scopes_and_initializer_order() {
    let source = r#"package app
type App struct{}
type Other struct{}
func (a *App) Run(ch chan Other, value interface{}) {
    a.before()
    { a := a.makeOther(); a.local() }
    a.after()
    if a := a.makeOther(); a.valid() { a.branch() }
    a.afterIf()
    for _, a := range a.values() { a.ranged() }
    func(a Other) { a.parameter() }(Other{})
    func() { a.captured() }()
    switch a := value.(type) { default: a.switched() }
    select { case a := <-ch: a.received(); default: a.defaulted() }
    { var a Other; a.variable() }
    a.final()
}
"#;
    let file = parse("pkg/app.go", source);
    let names: Vec<_> = file
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .map(|r| r.dst_name.as_str())
        .collect();
    for name in [
        "before",
        "makeOther",
        "after",
        "afterIf",
        "values",
        "captured",
        "defaulted",
        "final",
    ] {
        assert!(
            names.contains(&format!("App.{name}").as_str()),
            "missing bound receiver {name}: {names:?}"
        );
    }
    for name in [
        "local",
        "valid",
        "branch",
        "ranged",
        "parameter",
        "switched",
        "received",
        "variable",
    ] {
        assert!(
            names.contains(&name),
            "missing shadowed receiver {name}: {names:?}"
        );
        assert!(
            !names.contains(&format!("App.{name}").as_str()),
            "incorrect owner for {name}: {names:?}"
        );
    }
}

#[test]
fn a_receiver_binding_wins_over_a_same_named_file_import() {
    let files = [parse("app.go", "package app\nimport a \"external/decoy\"\ntype App struct{}\nfunc (a *App) Run() { a.prepare() }\nfunc (a *App) prepare() {}\n")];
    let caller = entity(&files[0], "App.Run");
    assert_eq!(
        call_targets(&batch(&files), caller),
        vec![entity(&files[0], "App.prepare")]
    );
    let call = files[0]
        .relations
        .iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    assert!(call.import_source.is_none());
}

#[test]
fn a_shadowed_receiver_cannot_become_an_import_or_free_function() {
    let source = "package app\nimport a \"external/decoy\"\ntype App struct{}\ntype Other struct{}\nfunc (a *App) Run() { { a := Other{}; a.prepare() }; a.prepare() }\nfunc (a *App) prepare() {}\nfunc (a *Other) prepare() {}\nfunc prepare() {}\n";
    let files = [parse("app.go", source)];
    let caller = entity(&files[0], "App.Run");
    let free = entity(&files[0], "prepare");
    let calls: Vec<_> = files[0]
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src_name == "App.Run")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .all(|r| r.receiver.as_deref() == Some("a") && r.import_source.is_none()));
    assert_eq!(calls[0].dst_name, "prepare");
    assert_eq!(calls[1].dst_name, "App.prepare");
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        assert!(!call_targets(&relations, caller).contains(&free));
    }
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("app.go"),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    let free = indexed
        .entities
        .iter()
        .find(|e| e.name == "prepare")
        .unwrap()
        .id;
    assert!(!indexed
        .relations
        .iter()
        .any(|r| r.dst.as_entity() == Some(free)));
}

/// One file, two methods of one type calling a third through their receiver,
/// plus the caller in the package's test file.
///
/// This is the `cli/cli` `CodespaceSelector` shape the same-file gap was
/// hand-checked on. `receiver` selects the pointer or value form so the two
/// declarations are graded on the same claim.
fn selector_fixture(receiver: &str) -> Vec<FileParseData> {
    vec![
        parse(
            "pkg/cmd/codespace/codespace_selector.go",
            &format!(
                "package codespace\n\
                 type CodespaceSelector struct {{ api apiClient }}\n\
                 func ({receiver}) Select(ctx context.Context) (*Codespace, error) {{\n\
                 \tcodespaces, err := cs.fetchCodespaces(ctx)\n\
                 \tif err != nil {{ return nil, err }}\n\
                 \treturn cs.chooseCodespace(ctx, codespaces)\n\
                 }}\n\
                 func ({receiver}) SelectName(ctx context.Context) (string, error) {{\n\
                 \tcodespaces, err := cs.fetchCodespaces(ctx)\n\
                 \tif err != nil {{ return \"\", err }}\n\
                 \treturn codespaces[0].Name, nil\n\
                 }}\n\
                 func ({receiver}) fetchCodespaces(ctx context.Context) ([]*Codespace, error) {{\n\
                 \treturn cs.api.ListCodespaces(ctx)\n\
                 }}\n\
                 func ({receiver}) chooseCodespace(ctx context.Context, in []*Codespace) (*Codespace, error) {{\n\
                 \treturn in[0], nil\n\
                 }}\n"
            ),
        ),
        parse(
            "pkg/cmd/codespace/codespace_selector_test.go",
            "package codespace\nfunc TestFetchCodespaces(t *testing.T) {\n\tsel := &CodespaceSelector{}\n\tsel.fetchCodespaces(nil)\n}\n",
        ),
    ]
}

/// A method calling another method of the same concrete type in the same file
/// resolves to the owner-qualified method entity, from every calling method,
/// under both a pointer and a value receiver.
///
/// The adapter emitted these calls with no receiver and a bare `dst_name`
/// while the method entity is stored owner-qualified, so the same-file tier
/// keyed a bare name against qualified names and missed, and the bare-leaf
/// fallback excludes the same file by design. Every such call produced no
/// `Calls` relation at all: on `cli/cli`, `CodespaceSelector.fetchCodespaces`
/// reported only its cross-file test caller, and a grep proxy counted about
/// 1,061 same-file receiver call sites across 464 methods in that corpus.
#[test]
fn same_file_receiver_calls_resolve_for_pointer_and_value_receivers() {
    for receiver in ["cs *CodespaceSelector", "cs CodespaceSelector"] {
        let files = selector_fixture(receiver);
        let select = entity(&files[0], "CodespaceSelector.Select");
        let select_name = entity(&files[0], "CodespaceSelector.SelectName");
        let fetch = entity(&files[0], "CodespaceSelector.fetchCodespaces");
        let choose = entity(&files[0], "CodespaceSelector.chooseCodespace");
        let test_caller = entity(&files[1], "TestFetchCodespaces");

        // The adapter has to hand the linker something a receiver-aware tier
        // can key on, or no tier below can resolve the call.
        let emitted: Vec<_> = files[0]
            .relations
            .iter()
            .filter(|r| {
                r.kind == RelationKind::Calls
                    && r.dst_name == "CodespaceSelector.fetchCodespaces"
                    && r.receiver.as_deref() == Some("cs")
            })
            .collect();
        assert_eq!(
            emitted.len(),
            2,
            "both call sites must leave the adapter owner-qualified for `{receiver}`: {:?}",
            files[0]
                .relations
                .iter()
                .filter(|r| r.kind == RelationKind::Calls)
                .map(|r| (&r.src_name, &r.dst_name, &r.receiver))
                .collect::<Vec<_>>()
        );

        for relations in [
            batch(&files),
            link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
        ] {
            assert_eq!(
                call_targets(&relations, select),
                {
                    let mut expected = vec![fetch, choose];
                    expected.sort();
                    expected
                },
                "`Select` must reach both same-file receiver calls for `{receiver}`"
            );
            assert_eq!(
                call_targets(&relations, select_name),
                vec![fetch],
                "`SelectName` must reach the same method for `{receiver}`"
            );
            let edge = relations
                .iter()
                .find(|r| {
                    r.kind == RelationKind::Calls
                        && r.src.as_entity() == Some(select)
                        && r.dst.as_entity() == Some(fetch)
                })
                .unwrap();
            assert_eq!(
                RelationResolution::of(edge),
                RelationResolution::TypeResolved,
                "a receiver call is resolved by its declared type, not guessed"
            );
            let sites = certified_sites(edge);
            assert_eq!(
                sites.len(),
                1,
                "`Select` calls `fetch` at one site for `{receiver}`, so the span check below \
                 cannot pass on an edge with none: {edge:?}"
            );
            assert!(sites.iter().all(|evidence| evidence.source_span.is_some()));

            // The cross-file caller that already resolved must keep resolving.
            assert!(
                call_targets(&relations, test_caller).contains(&fetch),
                "the test file's caller must still reach the method for `{receiver}`"
            );
        }
    }
}

/// A receiver call whose owner is declared twice in one package stays
/// unresolved rather than being guessed onto one of them, and the sibling
/// call in the same body still resolves.
#[test]
fn an_ambiguous_owner_leaves_the_receiver_call_unresolved() {
    let mut files = selector_fixture("cs *CodespaceSelector");
    files.push(parse(
        "pkg/cmd/codespace/duplicate.go",
        "package codespace\nfunc (cs *CodespaceSelector) fetchCodespaces(ctx context.Context) ([]*Codespace, error) { return nil, nil }\n",
    ));
    let select = entity(&files[0], "CodespaceSelector.Select");
    let choose = entity(&files[0], "CodespaceSelector.chooseCodespace");
    assert_eq!(
        call_targets(&batch(&files), select),
        vec![choose],
        "two declarations of one method are not proof of either"
    );
}

/// A method promoted onto the receiver's type by embedding still resolves.
///
/// Go promotes an embedded type's methods onto the embedder, and the call is
/// written on the receiver, so the adapter qualifies it with the receiver's
/// OWN type. No entity carries `App.helper`, so the owner-qualified lookup
/// that resolves a same-type call finds nothing and the call reached nothing
/// at all: qualifying the call name took this edge away, because the bare leaf
/// it used to carry resolved cross-file on name alone. The embedding walk is
/// declaration evidence and gives the edge back without that name guess.
#[test]
fn a_promoted_method_resolves_through_the_embedded_type() {
    let files = [
        parse(
            "pkg/base.go",
            "package app\ntype Base struct{}\nfunc (b *Base) helper() {}\n",
        ),
        parse(
            "pkg/app.go",
            "package app\ntype App struct{ *Base }\nfunc (a *App) Run() { a.helper() }\n",
        ),
    ];
    let caller = entity(&files[1], "App.Run");
    let promoted = entity(&files[0], "Base.helper");
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        assert_eq!(call_targets(&relations, caller), vec![promoted]);
    }
}

/// Promotion reaches through a chain of embeddings, and a free function of the
/// same name never stands in for one.
#[test]
fn promotion_walks_the_chain_and_never_takes_a_free_function() {
    let files = [
        parse(
            "pkg/root.go",
            "package app\ntype Root struct{}\nfunc (r *Root) helper() {}\nfunc helper() {}\n",
        ),
        parse("pkg/mid.go", "package app\ntype Mid struct{ Root }\n"),
        parse(
            "pkg/app.go",
            "package app\ntype App struct{ Mid }\nfunc (a *App) Run() { a.helper() }\n",
        ),
    ];
    let caller = entity(&files[2], "App.Run");
    let promoted = entity(&files[0], "Root.helper");
    let free = entity(&files[0], "helper");
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        assert_eq!(call_targets(&relations, caller), vec![promoted]);
        assert!(!call_targets(&relations, caller).contains(&free));
    }
}

/// The embedder's own method answers the call, exactly as Go's selector depth
/// rule decides it, and two types embedded at one depth answer neither.
#[test]
fn an_own_method_outranks_promotion_and_an_ambiguous_promotion_stays_unresolved() {
    let own = [
        parse(
            "pkg/base.go",
            "package app\ntype Base struct{}\nfunc (b *Base) helper() {}\n",
        ),
        parse(
            "pkg/app.go",
            "package app\ntype App struct{ *Base }\nfunc (a *App) helper() {}\nfunc (a *App) Run() { a.helper() }\n",
        ),
    ];
    for relations in [
        batch(&own),
        link_cross_file_incremental(&own, &incremental(&own)).unwrap(),
    ] {
        assert_eq!(
            call_targets(&relations, entity(&own[1], "App.Run")),
            vec![entity(&own[1], "App.helper")],
            "a method the embedder declares itself is never displaced by a promoted one"
        );
    }

    let ambiguous = [
        parse(
            "pkg/base.go",
            "package app\ntype Base struct{}\nfunc (b *Base) helper() {}\ntype Other struct{}\nfunc (o *Other) helper() {}\n",
        ),
        parse(
            "pkg/app.go",
            "package app\ntype App struct{\n\t*Base\n\t*Other\n}\nfunc (a *App) Run() { a.helper() }\n",
        ),
    ];
    for relations in [
        batch(&ambiguous),
        link_cross_file_incremental(&ambiguous, &incremental(&ambiguous)).unwrap(),
    ] {
        assert!(
            call_targets(&relations, entity(&ambiguous[1], "App.Run")).is_empty(),
            "two promotions at one depth are ambiguous in Go and neither is the answer"
        );
    }
}

/// A method promoted by a type embedded from ANOTHER package stays
/// unresolved, and is never answered by a name match.
///
/// `extract_embedded_types` keeps the qualifier, so the base reads `other.Base`
/// and the promoted lookup asks for `other.Base.helper`, which nothing in the
/// calling package declares. The walk is package-scoped on purpose: binding
/// the qualifier would need the file's import graph, which this tier does not
/// read. Until it does, the gap is disclosed rather than guessed. The decoy
/// `helper` entities exist precisely so a future refactor that let this fall
/// through to a bare-name tier fails here instead of minting a wrong edge.
#[test]
fn a_promotion_from_another_package_stays_unresolved_and_is_never_name_matched() {
    let files = [
        parse(
            "other/base.go",
            "package other
type Base struct{}
func (b *Base) helper() {}
",
        ),
        parse(
            "pkg/app.go",
            "package app
import \"example.com/m/other\"
type App struct{ *other.Base }
func (a *App) Run() { a.helper() }
",
        ),
        // Decoys in the calling package: a free function and an unrelated
        // type's method, both named `helper`.
        parse(
            "pkg/decoy.go",
            "package app
type Unrelated struct{}
func (u *Unrelated) helper() {}
func helper() {}
",
        ),
    ];
    let caller = entity(&files[1], "App.Run");
    // The negative means nothing unless the call reached the linker at all and
    // the decoys it must not take are really in the graph.
    assert_eq!(
        files[1]
            .relations
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .map(|r| (r.dst_name.as_str(), r.receiver.as_deref()))
            .collect::<Vec<_>>(),
        vec![("App.helper", Some("a"))],
        "the adapter must still hand the linker the qualified receiver call"
    );
    for decoy in ["Unrelated.helper", "helper"] {
        assert!(
            files[2].entities.iter().any(|e| e.name == decoy),
            "the decoy {decoy} must exist for this negative to mean anything"
        );
    }
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        assert!(
            call_targets(&relations, caller).is_empty(),
            "a cross-package promotion is a disclosed gap, never a name match: {:?}",
            call_targets(&relations, caller)
        );
    }
}
