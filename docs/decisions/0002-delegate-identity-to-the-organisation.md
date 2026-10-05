# 0002 — Delegate identity to the organisation's provider

**Status:** accepted

## Context

Organisations need their people to authenticate before querying their own data. The gateway could issue its own credentials, or it could verify credentials issued elsewhere.

The MCP specification settles the architecture. Under revision 2026-07-28 an MCP server is an OAuth 2.1 **resource server**: it validates tokens issued by a separate authorization server. The specification requires that a server validate tokens were issued specifically for it, that it publish Protected Resource Metadata (RFC 9728) so clients can discover the authorization server, and that it never forward a client's token to an upstream API.

## Decision

Each organisation registers the issuer and audience of its own identity provider. The gateway verifies the token signature, issuer and audience, extracts the verified email claim, and matches it against that organisation's allowlist to resolve a role. The gateway issues nothing.

## Consequences

- **No password or credential reaches this service.** The worst case for a breach here is far smaller than for a service holding credentials.
- **Offboarding works by itself.** Someone removed from the corporate directory stops being able to authenticate, with no action required here. A gateway holding its own accounts would quietly keep granting access to people who had left.
- **The organisation's own controls apply.** Multi-factor, conditional access and device posture are enforced where they already exist.
- **Email allowlists stay useful.** Verifying who someone is and deciding what they may do are different questions, and the second is answered here.
- **The cost is setup friction.** Each organisation must register an issuer and audience and map addresses to roles, which is more work than handing out an API key — and is the reason API keys remain the common shortcut.
