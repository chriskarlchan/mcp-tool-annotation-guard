# Changelog

All notable changes to this policy are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-05

First release.

### Added

- Sorts every MCP tool into **read**, **write** or **destructive** from its
  `readOnlyHint` and `destructiveHint` annotations. Tools without annotations
  are destructive unless `nameRules` or `unannotatedAs` say otherwise, and
  `toolOverrides` set a class directly.
- Caller access levels: every caller starts at `defaultLevel`, and `grants`
  raise it from verified roles, groups, scopes or the client ID
  (`callerAttributes`, `callerAttributeSeparator`).
- Filters `tools/list` responses (JSON, and SSE on the POST) so callers see
  only the tools their level allows.
- Refuses `tools/call` above the caller's level, calls to `blockedTools`, and
  calls to tools not yet seen in a list (`onUnknownTool`), before any part of
  the call reaches the MCP server. Refusals carry stable reason codes, and the
  default format matches Omni Gateway's native MCP access-control denial.
- Rug-pull protection: a tool's class can be raised but never lowered while
  the gateway runs.
- Stale-catalog protection, per-tenant catalogs (`catalogPartition`), catalog
  expiry and size limits.
- Audit mode (`mode: audit`): logs what would be refused without refusing or
  filtering anything.
- Structured log events that never contain tool arguments, results, tokens or
  claims.

### Compatibility

- Omni Gateway 1.11.4 or later (tested on 1.11.4 and 1.13.0 locally, and on
  1.14.4 as a Connected gateway). Not for Mule Gateway.
- MCP 2025-03-26 and 2025-06-18 over Streamable HTTP. On the legacy HTTP+SSE
  transport, calls are enforced but lists are not filtered.
- Identity providers: token shapes from Microsoft Entra ID, Okta, Auth0,
  Keycloak, Amazon Cognito and plain OAuth `scope`, verified by JWT
  Validation.

See [docs/overview.md](docs/overview.md) for limitations and
[docs/configuration.md](docs/configuration.md) for every property.

[1.0.0]: https://github.com/chriskarlchan/mcp-tool-annotation-guard/releases/tag/v1.0.0
