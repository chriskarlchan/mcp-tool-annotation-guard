# Deployment & Ordering

## Prerequisites

- **Omni Gateway 1.11.4 or later**, on an MCP server instance with **MCP Support**.
- **Gateway buffer limit ≥ the policy limits.** The gateway buffers request bodies up to `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES` (default 1 MB) and rejects larger ones with HTTP 500 before any policy runs. Keep it at least `limits.maxRequestBodyBytes` and `limits.maxListResponseBytes`. The guard logs its configured limits at start-up so you can compare.
- **Fail closed on Wasm failure.** If the policy's Wasm VM fails, Omni Gateway answers that request with HTTP 503 and does not forward it, then reloads the policy. This was observed on 1.14.4; no setting changes it.
- **One tool catalog per server, or `catalogPartition`.** Every caller must see the same definition for each tool name. If definitions differ per tenant, user or routed backend, set `catalogPartition` to the value that separates them; otherwise one caller's honest "read" listing could let another caller call a destructive tool.
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
- MCP Attribute-Based Access Control and MCP Global Access are independent: every policy must allow a call.

Apply the policy only to MCP server instances, or to the MCP path of an instance that also serves other paths.
