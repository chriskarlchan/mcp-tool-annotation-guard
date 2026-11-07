# Configuration

Every property is optional. An empty configuration gives every caller read-only access (see **Overview**). The API Manager form starts at the defaults listed below; a setting left out of a configuration file also uses its default.

## Start here

Most configurations need only the first few fields of the form:

1. **Caller roles or scopes** (`callerAttributes`): where the caller's roles, scopes or client ID come from. They must come from an authentication policy that runs earlier, such as JWT Validation. See [Identity providers](#identity-providers) for the expression to use.
2. **Grants** (`grants`): which role, scope or client ID gets which level. Callers without a matching grant stay at the **Default access level** (read).
3. **Blocked tools** (`blockedTools`), optional: tools no caller may use.

For a first rollout, also set **Mode** to `audit`: nothing is refused, and the log shows what would have been (example E).

**If your server's tools have no annotations**, they are all treated as destructive, so only callers with the destructive level see them. To open them up, classify them yourself with **Tool class overrides** or **Name rules**, and see example D.

**Leave the rest as it is** unless one of these applies:

| Fields | Change them when |
|---|---|
| Logging | You want an event for every allowed call, or the caller's roles in call events. |
| Advanced: tool catalog per tenant | The server shows different tools to different tenants or users (example G). |
| Advanced: refusal format | Your client doesn't show JSON-RPC errors to the model (use `toolResultError`, example H), or you want to add a hint such as who to ask for access. |
| Advanced: tool catalog expiry | You want agents to re-list tools periodically. Most clients list once per session. |
| Advanced: size limits | Your server has very large tool lists or requests. |

## How the settings combine

For every call, the guard answers two questions: **what class is the tool**, and **what level is the caller**. The call is allowed when the caller's level is at least the tool's class (none < read < write < destructive). The tool list shows exactly the tools the caller could call.

**The tool's class.** The first rule that applies wins:

1. **Blocked tools**: refused for everyone, always hidden.
2. **Tool class overrides**: the class you set.
3. **The tool's annotations**: `readOnlyHint: true` → read; `destructiveHint: false` → write; anything else → destructive. While the gateway runs, a tool's class can rise but is never lowered by what the server later says (rug-pull protection).
4. **Name rules**, only for tools with no annotations: the first pattern that matches.
5. **Class for tools without annotations**: destructive by default.

A call to a tool the guard hasn't seen in a list yet is refused `unknown_tool`, and the agent is told to list tools again. With **Calls to tools not seen in a list** set to `classifyByName`, steps 4 and 5 decide instead.

**The caller's level** is the highest of the **Default access level** and every grant the caller matches. Grants only raise a level; nothing lowers it.

**Good to know when mixing settings:**

- Name rules never override real annotations. To correct an annotated tool, use a tool class override (example H).
- A tool can't be both blocked and overridden; that is a configuration error.
- **Default access level** `none` plus grants turns the guard into an allow-list of callers (example C).
- **Mode** `audit` works with any configuration: the decisions are the same, but they are only logged.
- **Hide tools the caller can't use** off still checks every call; it only stops hiding tools from lists.

## Top-level properties

| Property | In the form | Type | Default | Description |
|---|---|---|---|---|
| `mode` | Mode | `enforce` \| `audit` | `enforce` | `audit` refuses nothing and filters nothing; it logs a `would_deny` event for every refusal it would have made. |
| `defaultLevel` | Default access level | `none` \| `read` \| `write` \| `destructive` | `read` | Access level every caller gets before grants. `none` means no tools. |
| `callerAttributes` | Caller roles or scopes | DataWeave expression | unset | Returns the caller's attributes: a string or an array of strings, taken from identity an earlier policy verified. See [Caller attributes](#caller-attributes). |
| `callerAttributeSeparator` | Separator for a single-string claim | string | unset | Splits a single-string result, for example `" "` for an OAuth `scope` claim. |
| `grants` | Grants (role to access level) | array of grant objects | `[]` | Raise the caller's level when they have a given attribute. The highest matching grant wins. |
| `blockedTools` | Blocked tools | array of strings | `[]` | Tool names refused for every caller and always hidden. |
| `toolOverrides` | Tool class overrides | array of override objects | `[]` | Admin classification. Wins over annotations and is never lowered or raised by what the server says. The tool counts as known even before it is listed. |
| `unannotatedAs` | Class for tools without annotations | `read` \| `write` \| `destructive` | `destructive` | Class for tools that have no annotations and match no name rule. |
| `nameRules` | Name rules for tools without annotations | ordered array of name-rule objects | `[]` | Classify unannotated tools by name. Never overrides real annotations. |
| `onUnknownTool` | Calls to tools not seen in a list | `deny` \| `classifyByName` | `deny` | What to do with a call for a tool the guard hasn't seen in a list. `classifyByName` uses the first matching name rule, else `unannotatedAs`. |
| `filterToolsList` | Hide tools the caller can't use | boolean | `true` | `false` enforces calls only; the guard still learns from lists. |
| `strictContradictions` | Treat contradictory annotations as destructive | boolean | `false` | When `true`, a tool that says both `readOnlyHint: true` and `destructiveHint: true` is destructive instead of read. |
| `logging` | Logging | object | | See [`logging`](#logging). |
| `catalogPartition` | Advanced: tool catalog per tenant | DataWeave expression | unset | Separates what the guard learns per partition (for example per tenant), for servers that show different tools to different callers. **Fails closed**: if set but it returns no usable string, calls are refused (`partition_unavailable`) and lists come back empty. |
| `denial` | Advanced: refusal format | object | | See [`denial`](#denial). |
| `catalog` | Advanced: tool catalog expiry | object | | See [`catalog`](#catalog). |
| `limits` | Advanced: size limits | object | | See [`limits`](#limits). |

Tool names are compared exactly: case-sensitive, no Unicode normalisation. All configuration refers to the names the **upstream** server uses, before any MCP Tool Mapping rename.

### `grants[]`

| Property | In the form | Type | Description |
|---|---|---|---|
| `attribute` | Role, scope or client ID | string, required | Caller attribute to match, for example `mcp.admin`. Exact, case-sensitive. |
| `level` | Access level | `read` \| `write` \| `destructive`, required | Level the caller gets at least. |

### `toolOverrides[]`

| Property | In the form | Type | Description |
|---|---|---|---|
| `name` | Tool name | string, required | Tool name. Must be unique and must not also be in `blockedTools`. |
| `class` | Class | `read` \| `write` \| `destructive`, required | Class to enforce. |

### `nameRules[]`

| Property | In the form | Type | Description |
|---|---|---|---|
| `pattern` | Name pattern (regular expression) | regular expression, required | Rust `regex` syntax, tested against the tool name. Unanchored unless you use `^` or `$`: **anchor with `^`** so that, for example, `^get_` doesn't also match `post_get_status`. An invalid pattern is a configuration error. |
| `class` | Class | `read` \| `write` \| `destructive`, required | Class for a matching tool. |

Rules are tried in order; the first match wins.

### `logging`

| Property | In the form | Type | Default | Description |
|---|---|---|---|---|
| `logAllowedCalls` | Log allowed calls | boolean | `false` | Log a `call_allowed` debug event for every allowed call. |
| `logCallerAttributes` | Include caller roles in log events | boolean | `false` | Include caller attributes in log events. Off by default; tokens, claims, tool arguments and results are never logged. |

### `denial`

| Property | In the form | Type | Default | Description |
|---|---|---|---|---|
| `style` | Refusal style | `jsonRpcError` \| `toolResultError` | `jsonRpcError` | `toolResultError` returns refusals as a tool result with `isError: true`, which many clients pass to the model; the reason is kept in `_meta`. Applies to `level_insufficient`, `tool_blocked`, `unknown_tool` and `partition_unavailable`. |
| `errorCode` | JSON-RPC error code | integer | `-32008` | JSON-RPC code for refusals. Must be in −32099…−32000 or outside −32768…−32000, and not a standard JSON-RPC code. |
| `httpStatus` | HTTP status | `200` \| `403` | `200` | HTTP status for refusals. Some clients treat non-2xx as a transport failure and never show the message to the model, hence the 200 default. |
| `includeRequiredLevel` | Say which level is required | boolean | `true` | Adds the required level to the message and `data`. Formatting only: the message always states the tool's class. |
| `revealGrantNames` | Say which roles would grant access | boolean | `false` | Lists the attributes that would grant access. May reveal role names. |
| `hint` | Extra text for refusals | string, ≤ 512 characters | unset | Appended to every refusal message, for example "Ask #platform-team for access." |

### `catalog`

| Property | In the form | Type | Default | Description |
|---|---|---|---|---|
| `maxAgeSeconds` | Maximum catalog age (seconds) | integer ≥ 0 | `0` (off) | When > 0, what the guard learned expires this many seconds after the last inspected list, and calls are refused `unknown_tool` until the agent re-lists. Most clients list once per session, so leave it off unless you want periodic re-listing. |

### `limits`

| Property | In the form | Type | Default | Description |
|---|---|---|---|---|
| `maxRequestBodyBytes` | Maximum request body (bytes) | integer ≥ 1024 | `1048576` | Larger POST bodies are refused `too_large`. |
| `maxListResponseBytes` | Maximum tool list response (bytes) | integer ≥ 1024 | `1048576` | Larger list responses pass through unfiltered, and calls fall back to unknown-tool handling until the next list the guard can inspect. A list over the gateway's own buffer limit is answered by the gateway with an error, and a list that no longer fits that limit once changed gets a JSON-RPC `internal_error`. Keep this at or below the gateway's buffer limit (see **Deployment & Ordering**). |
| `maxToolNameBytes` | Maximum tool name (bytes) | integer 1–1024 | `256` | Longer tool names in a call are refused `invalid_params`. |
| `maxBatchSize` | Maximum JSON-RPC batch size | integer 1–256 | `32` | Largest JSON-RPC batch (MCP 2025-03-26). |
| `maxCachedTools` | Maximum tools remembered per catalog | integer ≥ 1 | `5000` | Tools remembered per catalog. When full, new tools stay unknown (fail closed); nothing is evicted. |
| `maxCatalogBytes` | Maximum catalog size (bytes) | integer ≥ 4096 | `524288` | Size limit per catalog, with the same fail-closed behaviour. |
| `maxCatalogs` | Maximum catalogs kept | integer ≥ 1 | `1000` | Catalogs per API instance and configuration: one per partition, or a single one without `catalogPartition`. Nothing is evicted. When the limit is reached, a new partition's catalog is refused, its tools stay unknown, and its calls are refused `unknown_tool` (fail closed). |

## Caller attributes

`callerAttributes` reads identity that an **earlier authentication policy has already verified**. The guard works with any identity provider: it never talks to the provider and never parses the token. It reads the claims that JWT Validation has already checked, so the only thing that changes between providers is which claim holds the roles, groups or scopes.

| Source | Expression | Notes |
|---|---|---|
| JWT claims via JWT Validation | `#[authentication.properties.claims.<claim>]` | See **Identity providers** below for each provider's claim. |
| Client application via Client ID Enforcement | `#[authentication.clientId]` | |
| Local testing only | `#[attributes.headers['x-test-roles']]` | **Insecure**: anyone can set a header. |

A string result is one attribute (split by the separator if set); an array gives one attribute per string element. Anything else, or an evaluation error, gives no attributes, so the caller stays at `defaultLevel`. Grant values match exactly and are case-sensitive.

### Identity providers

| Provider | Claim in the access token | `callerAttributes` | `callerAttributeSeparator` |
|---|---|---|---|
| Microsoft Entra ID, app roles | `roles` (array) | `#[authentication.properties.claims.roles]` | |
| Microsoft Entra ID, delegated scopes | `scp` (space-separated string) | `#[authentication.properties.claims.scp]` | `" "` |
| Okta, groups | `groups` (array) | `#[authentication.properties.claims.groups]` | |
| Okta, scopes | `scp` (array) | `#[authentication.properties.claims.scp]` | |
| Auth0, roles | a namespaced custom claim, for example `https://example.com/roles` (array) | `#[authentication.properties.claims['https://example.com/roles']]` | |
| Auth0, permissions | `permissions` (array) | `#[authentication.properties.claims.permissions]` | |
| Keycloak, realm roles | `realm_access.roles` (array) | `#[authentication.properties.claims.realm_access.roles]` | |
| Keycloak, client roles | `resource_access.<client-id>.roles` (array) | `#[authentication.properties.claims.resource_access['<client-id>'].roles]` | |
| Amazon Cognito, groups | `cognito:groups` (array) | `#[authentication.properties.claims['cognito:groups']]` | |
| Any OAuth 2.0 server, scopes | `scope` (space-separated string) | `#[authentication.properties.claims.scope]` | `" "` |

Use square brackets for claim names that contain `:`, `/` or `-`, as in the Auth0, Keycloak client and Cognito rows.

**How this is tested.** Every row is covered by an integration test (`tests/identity_providers.rs`). The test signs tokens shaped like each provider's, has the built-in JWT Validation policy verify them on a local Omni Gateway, and then checks two things: a token carrying the granted value is let through, and a token with other values is refused. The `roles` row was also tested on a Connected Omni Gateway 1.14.4 with JWT Validation 0.12.0. The test checks token shapes; it does not sign in to the providers themselves. These were not tested: opaque tokens checked through OAuth 2.0 Token Introspection, and encrypted tokens (JWE).

**Provider notes.** The guard needs no provider-specific setup. What matters is that the token reaches JWT Validation with the claim in it:

- **All providers.** In JWT Validation, use the provider's key set (JWKS) URL, issuer and audience. The claim must be in the **access token**, not only in the ID token.
- **Microsoft Entra ID.** The key set is `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`. The issuer depends on the token version: `https://login.microsoftonline.com/<tenant-id>/v2.0` for v2.0 tokens, and `https://sts.windows.net/<tenant-id>/` for v1.0 tokens. Request tokens for **your own** app registration (its application ID or `api://…` URI), and use that as the audience. The gateway can't verify a token issued for Microsoft Graph. `roles` is present only when app roles are defined and assigned to the user or client application. Prefer app roles to groups: Entra's `groups` claim holds object IDs, not names, and is left out when a user belongs to too many groups.
- **Okta.** Use a custom authorization server (`https://<your-okta-domain>/oauth2/<server-id>`). Third parties can't verify access tokens from the Okta org authorization server. `groups` is in the token only after you add a groups claim to the authorization server.
- **Auth0.** Use your API's identifier as the audience. `permissions` needs RBAC and *Add Permissions in the Access Token* turned on for that API. Roles come from a custom claim added by an Action.
- **Keycloak.** The issuer is `https://<host>/realms/<realm>`. Add an audience mapper so the token's `aud` contains your API, because by default it is often only `account`.
- **Amazon Cognito.** Access tokens carry `client_id` but no `aud` claim, so set up JWT Validation's client ID check rather than its audience check.

## Deployment and policy order

Deployment prerequisites and the recommended policy order are on the **Deployment & Ordering** tab (`docs/deployment.md` in the repository).

## Refusals

Policy refusals use `denial.errorCode` (default `-32008`) and `denial.httpStatus` (default 200), with the request's `id`:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32008,
    "message": "Tool 'delete_branch' is classified as destructive. Your access level is read. Required level: destructive.",
    "data": {
      "policy": "mcp-tool-annotation-guard",
      "reason": "level_insufficient",
      "tool": "delete_branch",
      "toolClass": "destructive",
      "callerLevel": "read",
      "requiredLevel": "destructive"
    }
  }
}
```

| `reason` | When |
|---|---|
| `level_insufficient` | The tool's class is above the caller's level. |
| `tool_blocked` | The tool is in `blockedTools`. |
| `unknown_tool` | The guard hasn't seen the tool in a list it could inspect (or its knowledge is stale). The message tells the agent to call `tools/list` and retry. |
| `partition_unavailable` | `catalogPartition` is set but returned no usable value. |
| `batch_rejected` | A JSON-RPC batch contains a call that isn't permitted. |

Requests the guard can't safely interpret get JSON-RPC protocol errors with `data.reason` and `data.detail`: `parse_error` (400), `invalid_request` (400), `invalid_params` (200), `too_large` (413), `encoded` (415, compressed request bodies), `method_not_allowed` (405) and `internal_error` (500). All guard responses set `Cache-Control: no-store`. If the client accepts only `text/event-stream`, the response is sent as one SSE event.

## Logs

The guard writes one JSON event per line through the gateway's runtime log. To send the events to a SIEM or OpenTelemetry collector, use the gateway's own log forwarding (a `Configuration` resource with a Fluent Bit output such as `opentelemetry` or `splunk`).

| Event | Level | When |
|---|---|---|
| `call_denied` | info | A call was refused. |
| `would_deny` | info | Audit mode: a call would have been refused. |
| `list_filtered` | info | Tools were hidden from a list (up to 50 names). |
| `classification_upgraded` | info | A tool's class was raised. |
| `classification_downgrade_ignored` | warn | A server tried to lower a tool's class (possible rug pull). |
| `catalog_stale` / `catalog_fresh` | warn / info | The guard stopped / resumed trusting what it learned. |
| `request_rejected` | warn | A protocol error was returned. |
| `pin_capacity_exhausted` | warn | A limit was reached (`limit`: `maxCachedTools`, `maxCatalogBytes` or `maxCatalogs`); the tools concerned stay unknown. |
| `catalog_merge_retry_exhausted` | warn | What this worker learned is kept by this worker only, until a later save succeeds: other workers kept saving at the same moment, the shared store couldn't be read or written, or `maxCatalogs` was reached after this worker started using the catalog. |
| `partition_unavailable` | warn | `catalogPartition` returned no usable value. |

Repeated warnings of the same type are limited to one per minute per catalog.
