# Deployment & Ordering

## Prerequisites

- **Omni Gateway 1.11.4 or later**, on an MCP server instance with **MCP Support**.
- **Gateway buffer limit ≥ the policy limits.** The gateway buffers request bodies up to `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES` (default 1 MB) and rejects larger ones with HTTP 500 before any policy runs. Keep it at least `limits.maxRequestBodyBytes` and `limits.maxListResponseBytes`. The guard logs its configured limits at start-up so you can compare. A list response over the gateway's limit is answered by the gateway with an error, and the guard stops trusting what it learned until lists it can inspect show the tools again.
- **Fail closed on Wasm failure.** If the policy's Wasm VM fails, Omni Gateway answers that request with HTTP 503 and does not forward it, then reloads the policy. This was observed on 1.14.4; no setting changes it.
- **One tool catalog per server, or `catalogPartition`.** Every caller must see the same definition for each tool name. If definitions differ per tenant, user or routed backend, set `catalogPartition` to the value that separates them, read from verified identity; otherwise one caller's honest "read" listing could let another caller call a destructive tool.
- **Configuration errors fail closed.** API Manager accepts an invalid configuration (for example a reserved `denial.errorCode`), but the guard then answers every MCP request with HTTP 503 and the gateway log names the problem (`invalid mcp-tool-annotation-guard configuration: …`).

## Recommended policy order

Requests run top to bottom; responses run bottom to top.

1. **MCP Support** (first, required)
2. **Authentication**: JWT Validation, Client ID Enforcement, OAuth 2.0 Token Introspection or OpenID Connect
3. **MCP Tools Progressive Disclosure**, if used
4. **MCP Tool Mapping**, if used
5. Policies that change a request's method, tool name or arguments
6. **MCP Tool Annotation Guard**
7. **MCP Schema Validation**, if used
8. Response caches (P4A MCP Response Cache, HTTP Caching)

Rules behind this order:

- **After authentication**, so caller identity is available.
- **After MCP Tool Mapping**, so the guard sees the upstream's tool names in both directions. Placed before it, the guard refuses mapped names as `unknown_tool` (fails safe, but unusable).
- **After Progressive Disclosure**, which must run ahead of every policy that reads tool names. Placed before it, the guard refuses `search_tools` and `invoke_tool` as `unknown_tool`.
- **Nothing that short-circuits or changes requests between the guard and the upstream.** A response cache placed before the guard would serve one caller's cached list or result to another without a check. Place caches after the guard.
- **On an MCP Bridge instance**, place the guard directly after MCP Support, before MCP Schema Validation and the transcoding policies. Placed after MCP Transcoding, it fails safe but is unusable: the list is not filtered and every call is refused `unknown_tool`.
- **Before MCP Schema Validation.** With *Validate Tool Schema* on, Schema Validation answers `tools/list` itself, without asking the upstream. Placed before the guard, it serves the full list unfiltered, and the guard never learns it, so calls are refused `unknown_tool`. Placed after the guard, its *Tool Poisoning Detection* also removes poisoned tools before the guard learns them.
- **With *Validate Tool Schema* on, classify every tool yourself.** The list Schema Validation serves is built from the MCP server's Exchange asset and has no annotations (seen with MCP Schema Validation 1.3.0). The guard then classes every tool by `unannotatedAs`, destructive by default, so readers see nothing. Either list every tool in `toolOverrides`, or keep *Validate Tool Schema* off. Classes only go up, so tools learned as destructive while the option was on stay destructive after you turn it off. To start over, restart the gateway. Without a restart, list those tools in `toolOverrides`, which apply whatever the guard learned, or add `nameRules` that classify them: a change to `nameRules`, `unannotatedAs` or `strictContradictions` starts fresh catalogs. Changing one of these settings and then changing it back is not a reliable way to start over.
- **Schema Validation needs `properties` in every tool's input schema.** If a tool's `inputSchema` in the Exchange asset has no `properties`, Schema Validation answers `tools/list` with an internal error. Use `"properties": {}` for tools without arguments.
- MCP Attribute-Based Access Control and MCP Global Access are independent: every policy must allow a call.

Apply the policy only to MCP server instances, or to the MCP path of an instance that also serves other paths.

## Tested chain

The policy was tested on a Connected Omni Gateway 1.14.4 with this chain:

1. MCP Support 1.1.3
2. JWT Validation 0.12.0
3. MCP Tool Annotation Guard
4. MCP Schema Validation 1.3.0, with *Validate Tool Schema* off, and again with it on and every tool in `toolOverrides`

The test covered MCP 2025-03-26 and 2025-06-18, JSON and SSE responses to POST requests, and servers with and without MCP sessions (`Mcp-Session-Id`). For readers, editors and admins it checked that:

- each caller's level came from the roles in the JWT that JWT Validation verified, and requests without a valid token were refused before the guard;
- each list showed only the tools of the caller's level and, with *Validate Tool Schema* off, the tools shown reached the client unchanged, annotations included;
- calls above the caller's level were refused and never reached the MCP server, and permitted calls did.

Not covered by this test: SSE responses in which the server sends a request to the client before the list (see **Overview → Limitations**), and MCP 2026-07-28 servers (see **FAQ & See Also**).
