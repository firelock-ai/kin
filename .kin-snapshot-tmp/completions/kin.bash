#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Bash completion for kin CLI.
#
# Install:
#   source kin.bash
#   # or copy to /etc/bash_completion.d/kin
#
# To regenerate:
#   kin completions bash > kin.bash

_kin() {
    local i cur prev opts cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]}"; do
        case "${cmd},${i}" in
            ",$1")
                cmd="kin"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        kin)
            opts="init status commit log branch diff eject impact context trace search refs review history dead-code deps spec merge stash blame workspace run mcp auth remote push pull clone import checkout verify exec support audit approvals security semver release rollback bench migrate git intent traffic assistant work note feature todo open mode with reconcile shell overview completions update registry setup help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]]; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            ;;
    esac
}

complete -F _kin -o bashdefault -o default kin
