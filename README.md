# MCP Tool Annotation Guard

A custom policy for **MuleSoft Omni Gateway** that makes MCP servers least-privilege by default. It reads the safety annotations each MCP tool declares (`readOnlyHint`, `destructiveHint`), classes every tool as read, write or destructive, and lets each caller use only the tools their access level allows:

- **`tools/list`** responses are filtered, so callers only see tools they may use.
- **`tools/call`** requests are held and checked; refused calls are answered by the gateway and never reach the MCP server.

Unannotated tools count as destructive, new tools are handled automatically, a tool's class can't be silently lowered (rug-pull protection), and an audit mode lets you roll out safely. Callers get higher levels from identity the gateway has already verified: JWT roles or scopes, or the client ID.

## Quick start

With an empty configuration, every caller is read-only: tools that change or delete data are hidden, and calls to them are refused. To give some callers more, add the policy after your authentication policy and set three fields. For example, with roles in a JWT verified by JWT Validation:

```yaml
callerAttributes: "#[authentication.properties.claims.roles]"   # where roles come from
grants:                                                          # which role gets which level
  - { attribute: mcp.editor, level: write }
  - { attribute: mcp.admin,  level: destructive }
blockedTools: [delete_repository]                                # never, for anyone
```

Leave every other field as it is: the API Manager form starts at the safe defaults. Start with `mode: audit` to see what would be refused before enforcing. The Configuration doc has a [Start here](docs/configuration.md#start-here) section and explains [how the settings combine](docs/configuration.md#how-the-settings-combine); the examples cover [which setup fits you](docs/examples.md#which-example-fits-me).

## Platform

Built with the [Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) in Rust, compiled to `wasm32-wasip1`. Requires Omni Gateway 1.11.4 or later.

## Documentation

| Document | Contents |
|---|---|
| [docs/overview.md](docs/overview.md) | What the policy does, key features, limitations |
| [docs/configuration.md](docs/configuration.md) | Every property, identity providers, refusals, logs |
| [docs/examples.md](docs/examples.md) | Configurations A–H with the tools each caller sees |
| [docs/security.md](docs/security.md) | What it protects against and what not, trust model, fail-closed behaviour, logging, hardening checklist |
| [docs/deployment.md](docs/deployment.md) | Deployment prerequisites, recommended policy order |
| [docs/faq.md](docs/faq.md) | Common questions, related policies and specs |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |

The `docs/` files are the source of the policy's P4A catalog tabs.

## Repository layout

```
guard-core/        Pure Rust logic (no PDK dependencies) and its unit tests
src/               PDK policy glue (lib.rs) and pdk-unit tests (test.rs)
definition/        Policy schema (gcl.yaml)
tests/             Integration tests against a local Omni Gateway (pdk-test)
mock-mcp-server/   Zero-dependency Node MCP server used by the tests
playground/        Local gateway configuration for `make run`
docs/              P4A documentation tabs
```

## Development

Prerequisites: Anypoint CLI v4 with the PDK plugin, Rust 1.88+ with the `wasm32-wasip1` target, Docker, and make. See the [PDK prerequisites](https://docs.mulesoft.com/pdk/latest/policies-pdk-prerequisites).

```bash
make setup                          # once: install PDK build dependencies
(cd guard-core && cargo test)       # logic unit tests
make build                          # compile the Wasm policy
make test                           # pdk-unit tests + integration tests (Docker)
node mock-mcp-server/server.mjs     # mock MCP server on :8080 (switches: top of server.mjs)
make run                            # policy in a local gateway (playground/config/api.yaml)
```

`make test` and `make run` generate a local, disconnected `registration.yaml` on first use; it is git-ignored. If Docker can't be found, set `DOCKER_HOST` to your Docker socket (on Docker Desktop for macOS: `unix://$HOME/.docker/run/docker.sock`).

The integration tests run on Omni Gateway 1.13.0. To run them on another version, for example the minimum 1.11.4, set `PDK_TEST_FLEX_IMAGE_VERSION=1.11.4`.

Some integration tests are opt-in because they need extra setup or measure timing; run them with `cargo test --test <name> -- --ignored --nocapture`:

| Test | Checks |
|---|---|
| `latency` | Added latency on `tools/call` |
| `cache_placement` | Placement with the P4A MCP Response Cache (needs `MCP_RESPONSE_CACHE_DIR`, see the file header) |
| `log_forwarding` | Guard events reach the gateway's log forwarding outputs |
| `sse_server_request_first` | An SSE list whose server first sends a request to the client stalls (needs Node; see the file header) |

### Publishing

`make publish` publishes a development version (asset ID ending `-dev`, timestamped version) to Exchange in your configured organization; `make release` publishes the release version. See [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).
