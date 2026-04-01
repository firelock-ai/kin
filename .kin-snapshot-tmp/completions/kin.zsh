#compdef kin
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Zsh completion for kin CLI.
#
# Install:
#   cp kin.zsh ~/.zfunc/_kin
#   # ensure fpath includes ~/.zfunc, then: compinit
#
# To regenerate:
#   kin completions zsh > _kin

_kin() {
    local -a commands
    commands=(
        'init:Initialize a new Kin repository'
        'status:Show working copy status'
        'commit:Create a semantic commit'
        'log:Show semantic change log'
        'branch:Branch operations'
        'diff:Show entity diff between changes'
        'eject:Remove Kin and restore files'
        'impact:Show downstream impact of an entity'
        'context:Build a context pack for an entity'
        'trace:Trace a focal entity'
        'search:Search entities in the graph'
        'refs:Show upstream callers/importers/references'
        'review:Run semantic review on changes'
        'history:Show entity history'
        'dead-code:Find dead code'
        'deps:Show cross-repo dependencies'
        'spec:Manage specs'
        'merge:Semantic merge from another branch'
        'stash:Stash working copy state'
        'blame:Show blame for an entity'
        'workspace:Manage workspaces'
        'run:Run a validation command'
        'mcp:MCP server commands'
        'auth:Authenticate with KinLab'
        'remote:Manage remotes'
        'push:Push to remote'
        'pull:Pull changes from remote'
        'clone:Clone a repository'
        'import:Import a repository into Kin'
        'checkout:Restore a file from a specific change'
        'verify:Verify test coverage'
        'exec:Execute a command in a materialized workspace'
        'support:Show support and coverage report'
        'audit:Show audit trail'
        'approvals:Manage change approvals'
        'security:Scan for security patterns'
        'semver:Analyze semver impact'
        'release:Create a release snapshot'
        'rollback:Rollback to a previous change'
        'bench:Run benchmarks'
        'migrate:Run schema migrations'
        'git:Git interop commands'
        'intent:Manage agent intents'
        'traffic:Show traffic on a scope'
        'assistant:Manage assistant adapters'
        'work:Manage work items'
        'note:Manage annotations'
        'feature:Create a feature'
        'todo:Import inline TODOs'
        'open:Launch an editor in a materialized session'
        'mode:Manage repository mode'
        'with:Launch an assistant with Kin guidance'
        'reconcile:Reconcile session workspace changes'
        'shell:Open an interactive shell'
        'overview:Show codebase overview'
        'completions:Generate shell completions'
        'update:Update Kin to the latest release'
        'registry:Manage the global repository registry'
        'setup:First-time setup and health checks'
    )

    _describe -t commands 'kin command' commands
}

_kin "$@"
