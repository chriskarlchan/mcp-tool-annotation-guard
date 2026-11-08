# Security

## What it protects against

- **Agents calling tools above their caller's level.** A prompt-injected, over-eager or misconfigured agent can only call the tools its caller's access level allows. Every other call is refused by the gateway, and no part of it reaches the MCP server.
- **Tool lists that change under you.** A tool the vendor adds is classified the first time it is listed. A tool with no annotations is treated as destructive.
- **Silent downgrades (rug pulls).** While the gateway runs, a tool's class can be raised but never lowered. If a server later claims a destructive tool is read-only, the guard keeps it destructive and logs `classification_downgrade_ignored`.

## What it does not protect against

- **A server that lies from the start.** Annotations are hints written by the server, and the guard does not check that they are true. For servers you don't fully trust, set the class yourself with `toolOverrides` or refuse tools with `blockedTools`, and pair the guard with a tool-poisoning or drift-detection policy (see **FAQ & See Also**).
- **What a permitted tool does with its arguments.** The guard decides per tool, not per argument. A read tool can be called with any arguments.
- **Resources and prompts.** Only MCP tools are governed.
- **Weak authentication.** The guard relies on identity that an earlier policy has verified. It doesn't authenticate callers itself.
- **Callers who make the guard stop trusting what it learned.** Any caller who may list tools can do this, for example by closing the connection before a list arrives. Calls are then refused `unknown_tool` until a list shows their tools again (with `onUnknownTool: classifyByName`, they are decided by name, never with a lower class than the guard learned), and agents recover by listing tools, as the refusal tells them. This never lets through a call the guard would otherwise refuse. If callers you don't trust can reach the server, limit `tools/list` with a rate-limiting policy, and watch for `catalog_stale` events.

## Trust model

- **Tool classes come from the server's annotations**, unless you override them. `toolOverrides` and `blockedTools` always win over what the server says.
- **Caller levels come from verified identity only.** `callerAttributes` must read claims or a client ID that an authentication policy earlier in the chain has verified, such as JWT Validation or Client ID Enforcement. Never read a request header outside local testing: anyone can set a header and raise their own level.
- **The catalog partition comes from verified identity too.** `catalogPartition` must read the verified value that also decides which tools the server shows, such as a tenant ID claim. A caller who can choose its partition decides with another tenant's catalog, where a tool that is destructive for its own tenant may be read-only.
- **Levels only go up.** Every caller starts at `defaultLevel`, and grants can only raise it. With `defaultLevel: none`, only callers with a matching grant can use any tool.

## The security boundary is the call, not the list

Every `tools/call` is held by the gateway and checked before anything is forwarded. Hiding tools from `tools/list` is for usability and token savings. When a list isn't filtered, because `filterToolsList` is off, the list was too large or compressed to inspect, or it arrived on a transport the guard doesn't filter, calls are still checked.

## It fails closed

| Situation | What happens |
|---|---|
| A tool has no annotations, or annotations that declare neither hint | Treated as destructive. Without annotations, a name rule, `unannotatedAs` or an override can say otherwise; with annotations, only an override can |
| With `onUnknownTool: classifyByName`, the guard doesn't trust what it learned about a tool | The tool gets the higher of its learned class and its name's class, so not trusting never lowers a class |
| A call names a tool the guard hasn't seen in a list it could inspect | With `onUnknownTool: deny` (the default), refused `unknown_tool`, and the agent is told to list tools again. With `classifyByName`, classified by name rules, else as a tool without annotations |
| A list couldn't be inspected (compressed, too large or invalid) | The guard stops trusting what it learned (`catalog_stale`). Each tool is trusted again once a list the guard inspects shows it, so listing another page of a paginated list doesn't make the tools of other pages trusted |
| The gateway cut a list off before its end (buffer limit, upstream reset, timeout), or the client closed the connection before the list arrived | The same: the guard stops trusting what it learned (`catalog_stale`, reason `incomplete`) |
| An event stream ends without a complete list answer (for example, the upstream closes it part-way through the list event) | The stream passes unchanged, since clients don't read an unfinished event, and the guard stops trusting what it learned (`catalog_stale`, reason `response_invalid`) |
| The gateway refused the filtered list body | The client gets a JSON-RPC `internal_error` for that list request, not the unfiltered list. If the gateway refuses that error too, the list passes unchanged and the guard stops trusting what it learned (`catalog_stale`, reason `internal_error`) |
| A response a client could take for the list answer can't be validated (an `id` written differently, such as `"1"` for `1`, keys a client may read as the same member, such as `result` and `Result`, or JSON the guard can't parse) | The list passes unchanged and the guard stops trusting what it learned (`catalog_stale`, reason `response_invalid`) |
| The guard's tool memory is full (`maxCachedTools`, `maxCatalogBytes`) | New tools stay unknown (see above); nothing is evicted |
| `maxCatalogs` catalogs are in use | A new partition's catalog is refused, and its tools stay unknown (see above); nothing is evicted |
| `catalogPartition` is set but gives no value for a request | Refused `partition_unavailable` |
| A request can't be interpreted safely (malformed, compressed or too large) | Answered with a protocol error and not forwarded |
| A request repeats a key, also in a form a server may read as the same one (`name` and `Name`, or `name` and `name` followed by a NUL) | Refused `invalid_request` (`duplicate_keys`) and not forwarded. Some JSON parsers, such as Go's `encoding/json`, match keys regardless of case and keep the last one, so the guard and the server could otherwise read different tool names. Keys inside tool `arguments` are not compared this way |
| A request has a key a server may read as a JSON-RPC member without being one (`Method` for `method`, `Id` for `id`) | Refused `invalid_request` (`ambiguous_keys`) and not forwarded. Without a `method` key, a message with a `result` or `error` is a response to the guard, but a server that reads `Method` as `method` may run it as a call |
| A request's `Content-Type` names a charset other than UTF-8 (`charset=utf-7`, for example) | Refused `encoded` (415) and not forwarded. The guard reads JSON as UTF-8, as JSON requires, but some servers decode a body with the charset its client names, so the same bytes could name another tool |
| A request asks to upgrade the connection (`Upgrade: websocket`) | Refused `method_not_allowed` (405) and not forwarded. After an upgrade the connection no longer carries HTTP requests, so the guard couldn't check the calls on it. MCP over HTTP never upgrades |
| A GET, DELETE, OPTIONS or HEAD request carries a body (over HTTP/2 and HTTP/3 a body needs no `Content-Length`) | Refused `method_not_allowed` (405) and not forwarded. Only POST bodies are checked, so other methods must not carry one |
| The configuration is invalid | Every MCP request is answered with HTTP 503, and the gateway log names the problem |
| The policy's Wasm VM fails | Omni Gateway answers that request with HTTP 503 and does not forward it |

## What it logs, and what it never logs

- **Never logged:** tokens, tool arguments and tool results, and no claims other than the caller attributes below.
- **Caller attributes** (the roles, groups or scopes that `callerAttributes` reads) appear in log events only when `logging.logCallerAttributes` is on. It's off by default.
- **Refusals don't reveal role names** unless `denial.revealGrantNames` is on. It's off by default.
- **Guard responses are never cached.** Every response the guard writes sets `Cache-Control: no-store`. While filtering is active, so does every list the guard inspects, also when it hides nothing, and an existing `cacheScope` other than `"private"` is set to `"private"`, so a cache that honours them doesn't hand one caller's list to another.
- **Audit trail.** Refusals, would-be refusals in audit mode, hidden tools and class changes are logged as JSON events. Send them to a SIEM with the gateway's log forwarding (see **Configuration → Logs**).

## Hardening checklist

1. Put an authentication policy before the guard, and point `callerAttributes`, and `catalogPartition` if you set it, at its verified claims.
2. Keep `defaultLevel` at `read`, or use `none` to allow only callers with a grant.
3. Add tools no agent should ever use to `blockedTools`, and classify tools whose hints you don't trust with `toolOverrides`.
4. Check the server's annotations before you publish it with the MCP Server Safety ruleset, and catch later changes with a tool-poisoning or drift-detection policy.
5. Roll out with `mode: audit` first, then switch to `enforce`. In audit mode nothing is refused, not even requests the guard can't interpret.
6. Follow the policy order on the **Deployment & Ordering** tab. In particular, place response caches after the guard.

## Reporting a vulnerability

Please don't open a public issue. Report it privately as described in [SECURITY.md](https://github.com/chriskarlchan/mcp-tool-annotation-guard/blob/main/SECURITY.md).
