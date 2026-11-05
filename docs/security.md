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

## Trust model

- **Tool classes come from the server's annotations**, unless you override them. `toolOverrides` and `blockedTools` always win over what the server says.
- **Caller levels come from verified identity only.** `callerAttributes` must read claims or a client ID that an authentication policy earlier in the chain has verified, such as JWT Validation or Client ID Enforcement. Never read a request header outside local testing: anyone can set a header and raise their own level.
- **Levels only go up.** Every caller starts at `defaultLevel`, and grants can only raise it. With `defaultLevel: none`, only callers with a matching grant can use any tool.

## The security boundary is the call, not the list

Every `tools/call` is held by the gateway and checked before anything is forwarded. Hiding tools from `tools/list` is for usability and token savings. When a list isn't filtered, because `filterToolsList` is off, the list was too large or compressed to inspect, or it arrived on a transport the guard doesn't filter, calls are still checked.

## It fails closed

| Situation | What happens |
|---|---|
| A tool has no annotations | Treated as destructive, unless a name rule or override says otherwise |
| A call names a tool the guard hasn't seen in a list it could inspect | Refused `unknown_tool`; the agent is told to list tools again |
| A list couldn't be inspected (compressed, too large or invalid) | The guard stops trusting what it learned until it can inspect a list again (`catalog_stale`) |
| The guard's tool memory is full | New tools stay unknown and are refused; nothing is evicted |
| `catalogPartition` is set but gives no value for a request | Refused `partition_unavailable` |
| A request can't be interpreted safely (malformed, compressed or too large) | Answered with a protocol error and not forwarded |
| The configuration is invalid | Every MCP request is answered with HTTP 503, and the gateway log names the problem |
| The policy's Wasm VM fails | Omni Gateway answers that request with HTTP 503 and does not forward it |

## What it logs, and what it never logs

- **Never logged:** tokens, claims, tool arguments and tool results.
- **Caller roles** appear in log events only when `logging.logCallerAttributes` is on. It's off by default.
- **Refusals don't reveal role names** unless `denial.revealGrantNames` is on. It's off by default.
- **Guard responses are never cached.** Every response the guard writes sets `Cache-Control: no-store`.
- **Audit trail.** Refusals, would-be refusals in audit mode, hidden tools and class changes are logged as JSON events. Send them to a SIEM with the gateway's log forwarding (see **Configuration → Logs**).

## Hardening checklist

1. Put an authentication policy before the guard, and point `callerAttributes` at its verified claims.
2. Keep `defaultLevel` at `read`, or use `none` to allow only callers with a grant.
3. Add tools no agent should ever use to `blockedTools`, and classify tools whose hints you don't trust with `toolOverrides`.
4. Check the server's annotations before you publish it with the MCP Server Safety ruleset, and catch later changes with a tool-poisoning or drift-detection policy.
5. Roll out with `mode: audit` first, then switch to `enforce`.
6. Follow the policy order on the **Deployment & Ordering** tab. In particular, place response caches after the guard.

## Reporting a vulnerability

Please don't open a public issue. Report it privately as described in [SECURITY.md](https://github.com/chriskarlchan/mcp-tool-annotation-guard/blob/main/SECURITY.md).
