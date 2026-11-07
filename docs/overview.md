# Overview

**Least privilege by default, for every MCP server — including the ones you don't own. No tool lists to maintain.**

MCP Tool Annotation Guard is a **Security** policy for MCP server instances on MuleSoft Omni Gateway. It reads the safety hints each MCP tool declares about itself (`readOnlyHint`, `destructiveHint`), sorts every tool into **read**, **write** or **destructive**, and lets each caller use only the tools their **access level** allows.

## The problem

- Agents connected to an MCP server see every tool it offers, including ones that delete, merge or overwrite. A prompt-injected or over-eager agent can call them.
- Allow-lists of tool names go stale: the vendor adds a tool, renames one or changes what it does, and nobody updates the list.

## How it works

1. **Classify.** Each tool in a `tools/list` response is classed from its annotations: `readOnlyHint: true` → read, `destructiveHint: false` → write, anything else → destructive. Tools with no annotations are treated as destructive unless a name rule says otherwise.
2. **Work out the caller's level.** Every caller starts at `defaultLevel` (read by default). Grants raise it, based on identity the gateway has already verified: JWT roles or scopes, or the client ID.
3. **Filter the list.** `tools/list` responses only show tools at or below the caller's level.
4. **Block the call.** Every `tools/call` is held by the gateway and checked. A call above the caller's level is refused by the gateway with a clear, machine-readable message, and **no part of it reaches the MCP server**. This is the security boundary; list filtering is for usability and token savings.

## Key features

- **Fail-safe defaults.** Unannotated tools are destructive; tools the gateway hasn't seen in a list are refused (`unknown_tool`); configuration errors fail closed.
- **New tools handled automatically.** A tool the vendor adds is classified the first time it is listed, with no configuration change.
- **Rug-pull protection (pinning).** A tool's class can be raised but never silently lowered while the gateway runs. If a server later claims a destructive tool is read-only, the guard keeps it destructive and logs a warning.
- **Stale-catalog protection.** If the guard can't inspect a tool list (compressed, too large, invalid, or cut off by the gateway), it stops trusting what it learned before until it can inspect one again.
- **Audit mode.** Logs what it would have refused, without refusing or filtering anything, so you can roll out safely.
- **Clear refusals.** Stable reason codes for code (`level_insufficient`, `tool_blocked`, `unknown_tool`, …) and readable messages for models, so agents can self-correct. The defaults (JSON-RPC code `-32008`, HTTP 200) match Omni Gateway's native MCP access-control denial.
- **Low overhead.** Tool call *responses* are never buffered, parsed or changed. In our benchmark the guard added under 0.2 ms at p99 to `tools/call`.

## Design-time companion: the MCP Server Safety ruleset

The P4A <a href="https://www.p4a.ai/dashboard/rulesets/7f80e728-194c-4355-987c-16828865144c" target="_self">MCP Server Safety</a> ruleset (API Governance) checks at design time that every tool in an MCP server's Exchange manifest declares `readOnlyHint` or `destructiveHint` (rule `tool-side-effect-hint-declared`, severity violation). This policy enforces those hints at runtime, on live `tools/list` and `tools/call` traffic. **The ruleset gets servers annotated; the guard makes the annotations count.** Tools the ruleset reports as unannotated are exactly the ones the guard treats as destructive by default.

## With no configuration

An empty configuration is a safe, useful starting point: every caller is at **read** level. Read-only tools are listed and callable; write, destructive and unannotated tools are hidden and their calls refused.

## Limitations

- **Annotations are hints written by the server.** The guard does not check that they are true. It protects against honest-but-careless servers and later changes, not against a server that lies from the start. Use `toolOverrides` and `blockedTools` for tools you don't trust, and pair with tool-poisoning or drift-detection policies.
- **Tools only.** MCP resources and prompts are not governed. Tool arguments are not inspected.
- **Transports.** Calls are enforced on every transport. Lists are filtered on Streamable HTTP responses (JSON, and SSE on the POST). Lists delivered on a GET stream or over the legacy HTTP+SSE transport (2024-11-05) are not filtered, and their calls are decided only by `toolOverrides` and `onUnknownTool`. This includes a list the server sends again when a client resumes an interrupted SSE response with a GET and `Last-Event-ID`; calls are still checked.
- **SSE list responses are read whole.** When a server answers `tools/list` with an SSE stream, the guard waits for the whole stream before filtering it. Standard servers send the list and close the stream, which works. A server that first sends a request to the client (for example an elicitation) and waits for the reply stalls the list: the client never sees the request, and gets HTTP 504 when the gateway's upstream timeout expires (15 s in our test). Calls are not affected.
- **Protocol versions.** MCP 2025-03-26 and 2025-06-18.
- **One catalog per server.** The guard assumes an MCP server shows the same tool definitions to every caller. If definitions differ per tenant, set `catalogPartition` (see **Configuration**). During a rolling deploy of the MCP server, old and new server versions both answer for a while: a list the guard could inspect from an old version clears the distrust caused by one it couldn't inspect from a new version, so a tool whose class went up in the new version keeps its old class until the guard inspects a list from the new version.
- **Per replica.** What the guard has learned is shared by the workers of one gateway replica, not across replicas. A replica that hasn't served a list yet refuses calls with `unknown_tool` until it does; the refusal tells the agent to re-list.
- **Omni Gateway only**, version 1.11.4 or later. Not for Mule Gateway.
