# Examples

The examples below use a code-hosting MCP server with these tools:

| Tool | Annotations | Class |
|---|---|---|
| `list_issues` | `readOnlyHint: true` | read |
| `get_file` | `readOnlyHint: true` | read |
| `create_issue` | `readOnlyHint: false, destructiveHint: false` | write |
| `add_comment` | `destructiveHint: false` | write |
| `delete_branch` | `readOnlyHint: false, destructiveHint: true` | destructive |
| `merge_pull_request` | none | destructive (unannotated) |
| `delete_repository` | `destructiveHint: true` | destructive |

Each example lists the tools a caller sees in `tools/list`. Calls to any other tool are refused, and never reach the server.

The snippets use the configuration keys; in the API Manager form, each field shows a readable label (the **Configuration** tab lists both). Examples combine: for instance, add `mode: audit` from E to any of them for a first rollout, or `blockedTools` from B.

## Which example fits me?

| Your situation | Start with |
|---|---|
| I just want agents to stop calling anything that changes data | A (empty configuration) |
| Callers sign in through an identity provider (Entra ID, Okta, Auth0, Keycloak, Cognito) | B |
| Callers are client applications, without user sign-in | C |
| My server's tools have no annotations (for example an MCP Bridge server) | D, or H for a few named tools |
| I want to see what would be refused before enforcing | E |
| I want to try it locally, without an identity provider | F |
| My server shows different tools to different tenants | G |
| I don't agree with how the server annotates some tools, or my client hides JSON-RPC errors from the model | H |

## Trying it out

Put the guard in front of a test MCP server and compare its `tools/list` with and without the guard. First check whether the server's tools declare `readOnlyHint` or `destructiveHint`. A tool that declares neither is treated as destructive, so **with an empty configuration, a server with no annotations shows no tools at all**. That is the fail-safe default, not a fault. To see the tools of such a server, classify them yourself:

```yaml
toolOverrides:
  - { name: search_orders, class: read }    # use your server's tool names
  - { name: create_order,  class: write }
```

or classify them by name with `nameRules` (example D). To try the other levels without an identity provider, use example F. Whenever the guard hides tools, it logs a `list_filtered` event that names them.

If an agent shows no tools at all even at the highest level, compare with the upstream's own list without the guard. Some clients, Claude Code among them, drop a server's whole tool list when one tool in it is invalid (for example `readOnlyHint: "true"` as a string). The guard passes the list on as the server wrote it, so the fix is on the server, or hide that tool with `blockedTools`.

## A. Read-only for everyone (minimal)

*Intent: the safest start — every caller may only read.*

```yaml
{}
```

| Caller | Sees |
|---|---|
| Everyone | `list_issues`, `get_file` |

## B. Roles from your identity provider (JWT)

*Intent: let editors write and admins do everything, using roles in a JWT that JWT Validation has verified. One tool is off-limits to everyone.*

```yaml
callerAttributes: "#[authentication.properties.claims.roles]"
defaultLevel: read
grants:
  - { attribute: mcp.editor, level: write }
  - { attribute: mcp.admin,  level: destructive }
blockedTools: [delete_repository]
```

| Caller (`roles` claim) | Sees |
|---|---|
| no roles | `list_issues`, `get_file` |
| `mcp.editor` | + `create_issue`, `add_comment` |
| `mcp.admin` | + `delete_branch`, `merge_pull_request` |
| anyone | never `delete_repository` (refused `tool_blocked`) |

This uses the `roles` claim (Microsoft Entra ID app roles). For Okta, Auth0, Keycloak, Amazon Cognito or plain OAuth scopes, change only `callerAttributes` (and the separator for scopes); see **Identity providers** on the Configuration tab. Roles match exactly: `MCP.ADMIN` does not match `mcp.admin`.

## C. Client applications (no identity provider)

*Intent: give each client application its own level, using the client ID that Client ID Enforcement has verified. Unknown clients get nothing.*

```yaml
callerAttributes: "#[authentication.clientId]"
defaultLevel: none
grants:
  - { attribute: 3f2a9c-support-bot,   level: read }
  - { attribute: 81bd07-release-agent, level: destructive }
```

| Caller | Sees |
|---|---|
| any other client | no tools |
| `3f2a9c-support-bot` | `list_issues`, `get_file` |
| `81bd07-release-agent` | all seven tools |

## D. MCP Bridge server (no annotations)

*Intent: protect a server that has no annotations but puts the HTTP method in its tool names.* MCP Bridge names tools `<method>_<path>`, for example `get_issues`, `post_issues`, `put_issues_id`, `delete_branches_name`, and sends no annotations.

```yaml
nameRules:
  - { pattern: "^get_", class: read }
unannotatedAs: destructive
onUnknownTool: classifyByName
```

| Caller | Sees |
|---|---|
| Everyone | `get_issues` |

Every other tool stays destructive. Anchor patterns with `^`: `_get_` would also match `post_get_status`. Check the server's real `tools/list` first; names edited in the Bridge wizard may not follow the pattern. On a Bridge instance, place the guard directly after MCP Support (see the **Deployment & Ordering** tab).

## E. Roll out in audit mode, with OAuth scopes

*Intent: see what would be refused before enforcing anything.*

```yaml
mode: audit
callerAttributes: "#[authentication.properties.claims.scope]"
callerAttributeSeparator: " "
grants:
  - { attribute: "tools:write",  level: write }
  - { attribute: "tools:delete", level: destructive }
```

Every caller sees every tool and every call is forwarded. Each call that enforce mode would refuse logs a `would_deny` event with the tool, its class, the caller's level and the reason. Remove `mode: audit` when the logs look right.

## F. Local playground testing only (insecure)

*Intent: try the policy locally without an identity provider.*

```yaml
callerAttributes: "#[attributes.headers['x-test-roles']]"
callerAttributeSeparator: ","
grants:
  - { attribute: admin, level: destructive }
```

Send `x-test-roles: admin` to get destructive access. **Never use this in production**: anyone can set a header.

## G. Multi-tenant upstream

*Intent: the server shows different tool definitions to different tenants, so keep what the guard learns separate per tenant.*

```yaml
catalogPartition: "#[authentication.properties.claims.tid]"
callerAttributes: "#[authentication.properties.claims.roles]"
grants:
  - { attribute: mcp.admin, level: destructive }
```

If tenant A's `operate` tool is read-only but tenant B's is destructive, a tenant B reader can't call it because of what tenant A's list said. A request with no `tid` claim gets an empty list and its calls are refused `partition_unavailable`. Read the partition from a verified claim like this, never from a header a client sets.

## H. Correct a server's annotations, and refuse with tool results

*Intent: you know better than the server — `get_file` reads secrets, so treat it as write; and `merge_pull_request` is unannotated but you want editors to use it. Return refusals as tool results so the model sees them.*

```yaml
callerAttributes: "#[authentication.properties.claims.roles]"
grants:
  - { attribute: mcp.editor, level: write }
toolOverrides:
  - { name: get_file,           class: write }
  - { name: merge_pull_request, class: write }
denial:
  style: toolResultError
  hint: "Ask #platform-team for access."
```

| Caller | Sees |
|---|---|
| no roles | `list_issues` |
| `mcp.editor` | + `get_file`, `create_issue`, `add_comment`, `merge_pull_request` |

Overrides win over annotations and are the way to lower a class the guard has pinned.
