# Security policy

## Reporting a vulnerability

Please don't report security problems in public issues.

Report them privately through GitHub instead: on this repository's **Security** tab, choose **Report a vulnerability**. Include the policy version, the Omni Gateway version, the configuration involved (with any secrets removed), and the steps to reproduce.

You'll get an acknowledgement, and the fix and its release are coordinated with you before any details are made public.

## Supported versions

Security fixes go into the latest release.

## Scope

In scope: ways to get past the policy's checks, for example calling a tool above the caller's level, seeing tools in `tools/list` that should be hidden, or making the policy fail open.

Out of scope: problems in Omni Gateway itself, in other policies, or in the MCP servers behind the gateway. Report those to their owners. The policy trusts the annotations a server declares; a server that declares false annotations is a known limitation, described in [docs/overview.md](docs/overview.md).
