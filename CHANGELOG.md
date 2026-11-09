# Changelog

All notable changes to this policy are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-11-09

### Added

- `make clean` removes the build output.

### Changed

- Every setting in the API Manager form now has a description, including the
  fields inside grants, tool class overrides and name rules, and the tool name
  and batch size limits.

## [1.0.1] - 2026-11-08

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
- After a list the guard couldn't inspect, any list it could inspect made it
  trust what it had learned about every tool again, also a list that didn't
  show the tool, such as another page of a paginated list. A caller could
  list only another page and then call a tool whose class the server had
  raised in the list the guard couldn't inspect. A tool is now trusted again
  only once a list the guard inspects shows it, and `catalog.maxAgeSeconds`
  counts from the last list that showed the tool. After an upgrade from
  1.0.0, calls are refused `unknown_tool` until an agent lists tools again.
- With `onUnknownTool: classifyByName`, a tool the guard didn't trust any
  more was classified by its name only, so after a list the guard couldn't
  inspect, a destructive tool whose name matched a read rule could be called
  as read. A tool the guard has learned now gets the higher of its learned
  class and its name's class.
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
- A request could name one tool to the guard and another to the server when
  it repeated a key in a form some JSON parsers read as the same key, such as
  `"name":"search","Name":"delete_all"`. Go's `encoding/json` matches keys
  regardless of case and keeps the last one. Keys of the message and of a
  `tools/call`'s `params` that differ only in case or by a NUL are now refused
  as duplicates (`invalid_request` with detail `duplicate_keys`). In a list
  response, the same in the message, `result`, a tool entry or `annotations`
  makes the guard stop trusting what it learned (`catalog_stale` with reason
  `response_invalid`).
- A message with a `result` or `error` and a key such as `Method` instead of
  `method` passed the guard as a response. Servers that match keys
  regardless of case and take any message with a method for a request, as
  some Go MCP servers do, ran it as a call. Keys that a server may read as a
  JSON-RPC member (`jsonrpc`, `id`, `method`, `params`, `result` or `error`)
  without being one are now refused (`invalid_request` with detail
  `ambiguous_keys`). Keys are now also compared with `İ` read as `i`, as Go
  reads it.
- A request could name one tool to the guard and another to the server when
  its `Content-Type` named a charset other than UTF-8. The guard reads
  request bodies as UTF-8, but some servers decode them with the charset the
  client names: Express's `express.json()`, which the MCP TypeScript SDK
  uses, reads `+AG4-ame` as `name` in UTF-7. Such requests are now refused
  (`encoded`, HTTP 415).
- A request asking to upgrade the connection to a WebSocket passed the guard,
  and Omni Gateway 1.13.0 forwards such requests. If the server accepted,
  nothing sent on that connection was checked. Requests with an `Upgrade`
  header are now refused (`method_not_allowed`, HTTP 405).
- Over HTTP/2 and HTTP/3, a GET, DELETE, OPTIONS or HEAD request can carry a
  body without a `Content-Length` header. Such a body passed the guard
  unchecked and reached the server. These requests now pass only if their
  body is empty, and are refused otherwise (`method_not_allowed`, HTTP 405).
- Every `tools/call` decoded the whole catalog the guard had learned, and
  read it from the gateway's shared store one byte at a time, so large
  catalogs slowed every call: with 5,000 tools (the default
  `limits.maxCachedTools`), the guard added about 9 ms per call. A call now
  reads the catalog in one piece and decodes it only when another worker has
  changed it; with 5,000 tools the guard adds under 0.5 ms at p99. Catalogs
  are stored in the same format as before.
- Repeated warnings were limited to one a minute per event type and catalog,
  so one warning could hide another that said something else: a malformed
  request hid a request refused for duplicate keys right after it, and an
  attempt to lower one tool's class hid an attempt on another tool. Warnings
  are now limited per reason (`request_rejected`, `catalog_stale`), limit
  (`pin_capacity_exhausted`) or tool (`classification_downgrade_ignored`,
  `tool_definition_conflict`).

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

[1.0.2]: https://github.com/chriskarlchan/mcp-tool-annotation-guard/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/chriskarlchan/mcp-tool-annotation-guard/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/chriskarlchan/mcp-tool-annotation-guard/releases/tag/v1.0.0
