# FAQ & See Also

## FAQ

**Are annotations trustworthy?**
No. They are hints written by the MCP server, and the MCP specification warns clients not to trust them from untrusted servers. The guard treats them as safe defaults for honest-but-careless servers: unannotated tools are destructive, classes can't be lowered once seen (pinning), and you can override any tool with `toolOverrides` or `blockedTools`. It does not detect a server that lies from the start, and no gateway policy can, so review the hints before you publish the server (the MCP Server Safety ruleset below helps). To catch descriptors, annotations included, that change after you approved them, pair the guard with a drift or tool-poisoning check: the *Tool Poisoning Detection* option of MCP Schema Validation, or the P4A MCP Tool Drift Detection and MCP Tool Poisoning Detection policies (see **See Also**).

**What if a server has no annotations?**
Every tool is classed by `unannotatedAs`, destructive by default, so readers see nothing. Add `nameRules` if the names encode what tools do (MCP Bridge names start with the HTTP method: see example D), or classify tools with `toolOverrides`.

**Why did my call get `unknown_tool`?**
The guard hasn't seen the tool in a `tools/list` response it could inspect. Common causes: the agent called a tool without listing first; the request reached a gateway replica that hasn't served a list yet; the last list couldn't be inspected (compressed, too large or invalid), so the guard stopped trusting what it learned; `catalog.maxAgeSeconds` expired; or the tool name differs in case or spelling. The fix is usually to call `tools/list` and retry, as the message says. For critical tools, add a `toolOverrides` entry; it makes the tool known without a list.

**What happens on a new replica or after a restart?**
What the guard learned is shared by the workers of one replica and survives a policy reload, but it is not shared across replicas and is lost when a replica restarts. Until that replica serves a list, calls are refused `unknown_tool`. Omni Gateway has no session affinity for MCP; if you need it, configure it on the load balancer (for example on `Mcp-Session-Id`). `toolOverrides` and `onUnknownTool: classifyByName` also help.

**Which identity providers does it work with?**
Any provider whose tokens JWT Validation can verify. The guard never contacts the provider; it reads the verified claims. You only choose the claim in `callerAttributes`. Microsoft Entra ID, Okta, Auth0, Keycloak, Amazon Cognito and plain OAuth scopes are each covered by an integration test using that provider's token shape (see **Configuration → Identity providers**). Without an identity provider, use the client ID from Client ID Enforcement (example C).

**Does it inspect or change tool results?**
No. `tools/call` responses are passed through untouched and never buffered. Only `tools/list` responses are parsed and filtered.

**Does it work with MCP Tool Mapping, Progressive Disclosure, ABAC and response caches?**
Yes, in the right order (see **Configuration → Recommended policy order**). Place MCP Tool Mapping and MCP Tools Progressive Disclosure **before** the guard; all configuration then uses the upstream's tool names. MCP Attribute-Based Access Control and MCP Global Access are independent checks: every policy must allow a call. Place response caches **after** the guard, so every cache hit is still checked and filtered per caller.

**How does this relate to the MCP Server Safety ruleset?**
They cover the same hints at two stages. The <a href="https://www.p4a.ai/dashboard/rulesets/7f80e728-194c-4355-987c-16828865144c" target="_self">MCP Server Safety</a> ruleset runs in API Governance on the manifest published to Exchange: it reports tools that declare neither `readOnlyHint` nor `destructiveHint` before the server is deployed, but it blocks nothing at runtime and can't see tools added or changed after publication. The guard runs on live traffic: `readOnlyHint: true` → read, `destructiveHint: false` → write, `destructiveHint: true` → destructive. A tool that declares neither — exactly what the ruleset reports — is classed by `unannotatedAs`, destructive by default, so it is hidden and its calls refused. Neither checks that a hint is true. The ruleset's `openWorldHint` warning has no effect on the guard in this version.

**What does it cost in latency?**
In a benchmark of 1,000 `tools/call` requests, the guard added under 0.2 ms at p99 and about 0.12 ms at p50. List responses are buffered and rewritten, which costs more, but agents list rarely.

**Does it support the legacy HTTP+SSE transport?**
Partly. Calls are still enforced, but tool lists arrive on the GET stream, which the guard doesn't filter, and the guard can't learn from them. Calls are then decided only by `toolOverrides` and `onUnknownTool`, so configure those for legacy servers. Streamable HTTP (MCP 2025-03-26 and 2025-06-18) is fully supported.

**Does it work with clients that speak MCP 2026-07-28?**
Yes, through the fallback those clients use today. Claude Code, for example, first tries 2026-07-28 and, when the server answers as a 2025 server, continues with 2025-06-18; MCP Support supports 2025-06-18 and earlier. Tested end to end with Claude Code 2.1.291 as reader, editor and admin: each saw only the tools of its level, and the tools it called reached the server. Against a server that speaks 2026-07-28 itself, the guard still filters lists and decides calls from the request body, but this version doesn't claim 2026-07-28: a filtered list keeps the server's `cacheScope`, so a shared MCP-aware cache could hand one caller's list to another. Full support is planned for the next version.

**My server shows different tools to different tenants. Is that a problem?**
Yes, unless you set `catalogPartition`. The guard assumes every caller sees the same definition for each tool name. Set `catalogPartition` to the value that separates the definitions, such as a tenant ID claim (example G).

**How do I roll out safely?**
Start with `mode: audit` (example E). Nothing is refused or hidden; each would-be refusal is logged as `would_deny`. When the logs show only what you expect, switch to `enforce`.

## See Also

**Specifications**
- [MCP specification — Tools and tool annotations (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

**P4A**
- <a href="https://www.p4a.ai/dashboard/rulesets/7f80e728-194c-4355-987c-16828865144c" target="_self">MCP Server Safety ruleset</a> — the design-time companion: reports tools that declare no side-effect hints, which this policy enforces at runtime.
- <a href="https://www.p4a.ai/dashboard/policies/a2d61f3b-3807-4091-8fa5-da2ccd380c11" target="_self">MCP Response Cache</a> — caches lists and allowlisted read-only calls. It **must** run after the guard (closer to the upstream): a cache placed before the guard serves one caller's list or result to another without a check.
- <a href="https://www.p4a.ai/dashboard/policies/8dd07609-d805-4937-a919-418db46eb7f3" target="_self">MCP Tool Poisoning Detection (Exchange)</a> — compares each `tools/list` with the tool set published in Exchange and can remove changed, look-alike or injected tools. Place it after the guard, so poisoned tools are removed before the guard learns them.
- <a href="https://www.p4a.ai/dashboard/policies/2cf50b1f-226e-4bad-b750-7297f16af410" target="_self">MCP Tool Poisoning Detection (A²D)</a> — the same checks against a tool set pinned in A²D, optionally also scanning tool results. Same placement.
- <a href="https://www.p4a.ai/dashboard/policies/9d3136c2-b272-42ae-88b7-32749f93cc2f" target="_self">MCP Tool Drift Detection (Exchange)</a> — reports, and optionally removes, tools whose descriptor (annotations included) no longer matches the Exchange asset. It catches changes across replicas and restarts, where the guard's pinning starts over. Same placement.
- <a href="https://www.p4a.ai/dashboard/policies/ae240918-834a-45fc-9b43-bac0fe2021f2" target="_self">MCP Tool Drift Detection (A²D)</a> — the same with the trusted tool set pinned in A²D. Same placement.
- <a href="https://www.p4a.ai/dashboard/policies/acfec93f-35c9-4582-9d74-934474749a1c" target="_self">Approval-to-Execution Binding</a> — checks that a `tools/call` is exactly the call an approver signed, for example a destructive tool that admins may call only with approval. Both must allow the call; place it before the guard, because it can strip its approval envelope from the request.

**MuleSoft Omni Gateway policies**
- [MCP Support](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-support) — adds MCP support to an MCP server instance; required, and must come first.
- [JWT Validation](https://docs.mulesoft.com/gateway/latest/policies-included-jwt-validation) — validates the caller's JWT, whose roles or scopes feed `callerAttributes`.
- [MCP Tools Progressive Disclosure](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-progressive-disclosure) — exposes tools on demand through `search_tools` and `invoke_tool` to save context tokens. Place it before the guard; `search_tools` then finds only tools the caller may call.
- [MCP Tool Mapping](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-tool-mapping) — renames tools and their descriptions, in both directions. Place it before the guard, so the guard sees the upstream's names.
- [MCP Attribute-Based Access Control](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-attribute-access-control) — allows or denies tools, resources and prompts with Cedar rules over caller attributes such as tier, IP, headers or claims. Independent of the guard: both must allow a call.
- [MCP Global Access](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-global-access) — allow and block rules by tool, prompt or resource name, for every caller; it filters lists too. Independent of the guard: both must allow a call.
- [Configuring MCP access control policies](https://docs.mulesoft.com/gateway/latest/policies-mcp-access-control-together) — how Global Access, Tool Mapping and Attribute-Based Access Control combine.
- [MCP Schema Validation](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-schema-validation) — validates requests against the MCP specification. Its *Tool Poisoning Detection* option compares the upstream `tools/list` with the Exchange asset. Place it after the guard: with *Validate Tool Schema* on, it answers `tools/list` itself, so a guard placed after it never sees the list.
- [MCP Payload Optimization](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-payload-optimization) — reduces tool-result tokens. Compatible in any order, because the guard never reads tool results.
- [HTTP Caching](https://docs.mulesoft.com/gateway/latest/policies-included-http-caching) — caches HTTP responses. Like any response cache, it **must** run after the guard.
- [Create MCP servers with MCP Bridge](https://docs.mulesoft.com/general/exp-services-create-mcp-server) — a Bridge instance runs MCP Support → MCP Schema Validation → MCP Transcoding Router → MCP Transcoding, and its tools have no annotations. Place the guard directly after MCP Support; see example D for `nameRules`.

**Framework**
- [Omni Gateway Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview)
