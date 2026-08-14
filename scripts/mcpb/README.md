# Kin for Claude Desktop

Kin keeps a living map of the software itself, so Claude answers from a graph of entities,
relationships, changes, and provenance rather than from raw file search.

The extension runs Kin's MCP server on your machine over stdio, against one repository you
choose in the extension settings. Claude gets `semantic_locate`, `semantic_search`,
`get_context_pack`, `trace_data_flow`, `impact_analysis`, and `find_references`, and
answers them from that graph.

## Setup

Choose the Kin workspace in the extension settings. That directory has to carry `.kin/`.
If it does not, run `kin init .` there first, otherwise the server stops and says so.

You need Node 20 or newer. On first run the extension starts the published
`@kinlab/kin-mcp` launcher, which downloads the matching Kin release archive from
`https://github.com/firelock-ai/kin/releases/download` and caches it locally. macOS and
Windows are the supported platforms.

## Privacy Policy

https://kinlab.ai/privacy

Every network exit the CLI, the daemon, and this launcher can make is enumerated in
https://github.com/firelock-ai/kin/blob/main/docs/security/what-leaves-the-machine.md.

## Support

Report problems at https://github.com/firelock-ai/kin/issues. The core is Apache-2.0 at
https://github.com/firelock-ai/kin.
