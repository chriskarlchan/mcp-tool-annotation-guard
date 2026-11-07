# Changelog

All notable changes to this policy are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.1] - Unreleased

### Fixed

- A tool's class could be lowered, or a list the guard couldn't inspect could
  be forgotten, when two gateway workers saved what they learned at the same
  time. Every save now merges with the latest shared copy, and retries when
  another worker saved first.
- With more than `limits.maxCatalogs` catalogs in use, the least recently used
  catalog was evicted, and a destructive tool in it could be learned again as
  read. Nothing is evicted now: once the limit is reached, a new partition's
  catalog is refused (`pin_capacity_exhausted` with `limit: maxCatalogs`), and
  its tools stay unknown.
- If `limits.maxCatalogs` was reached after a worker started using a catalog
  that only it held, the worker stopped updating it: it learned no new tools
  and kept trusting what it had learned after a list it couldn't inspect. It
  now keeps its own copy up to date (`catalog_merge_retry_exhausted`).
- After a classification setting was changed and then changed back, a worker
  could keep deciding with what it had learned before the first change. It
  now drops its copy once the shared catalog is gone.
- When another worker saved at the same moment, the log could report
  `catalog_fresh` while the guard still didn't trust the catalog, or
  `tool_classified` for a tool that didn't fit. Log events now describe what
  the worker decides with.
- The Exchange metadata declared a minimum runtime of 1.6.1. It now declares
  1.11.4, and `make publish` and `make release` check this before uploading.
- A filtered SSE list whose JSON spanned several `data:` lines reached clients
  as incomplete JSON. Each line is now sent as its own `data:` line.
- A list that the gateway cut off after its headers (over the gateway's buffer
  limit, an upstream reset or a timeout) left the guard trusting what it had
  learned before. The guard now stops trusting it (`catalog_stale` with
  reason `incomplete`) until it can inspect a list again.
- A list starting with a byte-order mark, as JSON or SSE, passed unfiltered,
  and calls to its tools were refused `unknown_tool`. The mark is now accepted
  and kept.
- Lists that clients read without trouble were treated as impossible to
  inspect, so they passed unfiltered and calls were refused `unknown_tool`:
  SSE streams with JSON events that aren't the list response (a heartbeat such
  as `{"type":"ping"}`, for example), SSE streams with invalid UTF-8 (now read
  as U+FFFD, as clients read them), and charset labels such as `utf8`.
- A response that a client could take for the answer to a list request, but
  the guard didn't recognise, passed unfiltered next to the filtered list: an
  `id` written differently (`"1"` or `1.0` for `1`), JSON that JavaScript
  clients parse but the guard can't (numbers out of range, unpaired
  surrogates, deep nesting), or a garbled byte-order mark at the start of an
  SSE stream. Such a list now passes unchanged, and the guard stops trusting
  what it learned (`catalog_stale` with reason `response_invalid`).
- When the gateway refused a filtered list body, the unfiltered list reached
  the client. The client now gets a JSON-RPC `internal_error` for that list
  request instead. If the gateway refuses that error too, the list passes
  unchanged and the guard stops trusting what it learned (`catalog_stale`
  with reason `internal_error`).

### Changed

- While filtering is active (`mode: enforce` and `filterToolsList` on), every
  list the guard inspects is sent with `Cache-Control: no-store`, also when no
  tool was hidden, and an existing `result.cacheScope` other than `"private"`
  is set to `"private"`.
- `limits.maxCatalogs` now counts catalogs per API instance and
  configuration, and is a hard limit instead of an eviction threshold.

### Compatibility

- Omni Gateway 1.11.4 or later (tested on 1.11.4 and 1.13.0 locally, and on
  1.14.4 as a Connected gateway).
- Tested on a Connected gateway with the chain MCP Support 1.1.3 → JWT
  Validation 0.12.0 → this policy → MCP Schema Validation 1.3.0: JSON and SSE
  responses, with and without MCP sessions, MCP 2025-03-26 and 2025-06-18.
  With Schema Validation's *Validate Tool Schema* on, the tool list it serves
  has no annotations; see **Deployment & Ordering**.

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

[1.0.1]: https://github.com/chriskarlchan/mcp-tool-annotation-guard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/chriskarlchan/mcp-tool-annotation-guard/releases/tag/v1.0.0
