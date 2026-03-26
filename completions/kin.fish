# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Fish completion for kin CLI.
#
# Install:
#   cp kin.fish ~/.config/fish/completions/
#
# To regenerate:
#   kin completions fish > kin.fish

# Disable file completions for the first argument
complete -c kin -f

# Main subcommands
complete -c kin -n __fish_use_subcommand -a init -d 'Initialize a new Kin repository'
complete -c kin -n __fish_use_subcommand -a status -d 'Show working copy status'
complete -c kin -n __fish_use_subcommand -a commit -d 'Create a semantic commit'
complete -c kin -n __fish_use_subcommand -a log -d 'Show semantic change log'
complete -c kin -n __fish_use_subcommand -a branch -d 'Branch operations'
complete -c kin -n __fish_use_subcommand -a diff -d 'Show entity diff between changes'
complete -c kin -n __fish_use_subcommand -a eject -d 'Remove Kin and restore files'
complete -c kin -n __fish_use_subcommand -a impact -d 'Show downstream impact of an entity'
complete -c kin -n __fish_use_subcommand -a context -d 'Build a context pack for an entity'
complete -c kin -n __fish_use_subcommand -a trace -d 'Trace a focal entity'
complete -c kin -n __fish_use_subcommand -a search -d 'Search entities in the graph'
complete -c kin -n __fish_use_subcommand -a refs -d 'Show upstream callers/importers/references'
complete -c kin -n __fish_use_subcommand -a review -d 'Run semantic review on changes'
complete -c kin -n __fish_use_subcommand -a history -d 'Show entity history'
complete -c kin -n __fish_use_subcommand -a dead-code -d 'Find dead code'
complete -c kin -n __fish_use_subcommand -a deps -d 'Show cross-repo dependencies'
complete -c kin -n __fish_use_subcommand -a spec -d 'Manage specs'
complete -c kin -n __fish_use_subcommand -a merge -d 'Semantic merge from another branch'
complete -c kin -n __fish_use_subcommand -a stash -d 'Stash working copy state'
complete -c kin -n __fish_use_subcommand -a blame -d 'Show blame for an entity'
complete -c kin -n __fish_use_subcommand -a workspace -d 'Manage workspaces'
complete -c kin -n __fish_use_subcommand -a run -d 'Run a validation command'
complete -c kin -n __fish_use_subcommand -a mcp -d 'MCP server commands'
complete -c kin -n __fish_use_subcommand -a auth -d 'Authenticate with KinLab'
complete -c kin -n __fish_use_subcommand -a remote -d 'Manage remotes'
complete -c kin -n __fish_use_subcommand -a push -d 'Push to remote'
complete -c kin -n __fish_use_subcommand -a pull -d 'Pull changes from remote'
complete -c kin -n __fish_use_subcommand -a clone -d 'Clone a repository'
complete -c kin -n __fish_use_subcommand -a import -d 'Import a repository into Kin'
complete -c kin -n __fish_use_subcommand -a checkout -d 'Restore a file from a specific change'
complete -c kin -n __fish_use_subcommand -a verify -d 'Verify test coverage'
complete -c kin -n __fish_use_subcommand -a exec -d 'Execute a command in a materialized workspace'
complete -c kin -n __fish_use_subcommand -a support -d 'Show support and coverage report'
complete -c kin -n __fish_use_subcommand -a audit -d 'Show audit trail'
complete -c kin -n __fish_use_subcommand -a approvals -d 'Manage change approvals'
complete -c kin -n __fish_use_subcommand -a security -d 'Scan for security patterns'
complete -c kin -n __fish_use_subcommand -a semver -d 'Analyze semver impact'
complete -c kin -n __fish_use_subcommand -a release -d 'Create a release snapshot'
complete -c kin -n __fish_use_subcommand -a rollback -d 'Rollback to a previous change'
complete -c kin -n __fish_use_subcommand -a bench -d 'Run benchmarks'
complete -c kin -n __fish_use_subcommand -a migrate -d 'Run schema migrations'
complete -c kin -n __fish_use_subcommand -a git -d 'Git interop commands'
complete -c kin -n __fish_use_subcommand -a intent -d 'Manage agent intents'
complete -c kin -n __fish_use_subcommand -a traffic -d 'Show traffic on a scope'
complete -c kin -n __fish_use_subcommand -a assistant -d 'Manage assistant adapters'
complete -c kin -n __fish_use_subcommand -a work -d 'Manage work items'
complete -c kin -n __fish_use_subcommand -a note -d 'Manage annotations'
complete -c kin -n __fish_use_subcommand -a feature -d 'Create a feature'
complete -c kin -n __fish_use_subcommand -a todo -d 'Import inline TODOs'
complete -c kin -n __fish_use_subcommand -a open -d 'Launch an editor in a materialized session'
complete -c kin -n __fish_use_subcommand -a mode -d 'Manage repository mode'
complete -c kin -n __fish_use_subcommand -a with -d 'Launch an assistant with Kin guidance'
complete -c kin -n __fish_use_subcommand -a reconcile -d 'Reconcile session workspace changes'
complete -c kin -n __fish_use_subcommand -a shell -d 'Open an interactive shell'
complete -c kin -n __fish_use_subcommand -a overview -d 'Show codebase overview'
complete -c kin -n __fish_use_subcommand -a completions -d 'Generate shell completions'
complete -c kin -n __fish_use_subcommand -a update -d 'Update Kin to the latest release'
complete -c kin -n __fish_use_subcommand -a registry -d 'Manage the global repository registry'
complete -c kin -n __fish_use_subcommand -a setup -d 'First-time setup and health checks'

# Completions subcommand
complete -c kin -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish' -d 'Shell type'
