# Security Policy

counter-sign is an authorization protocol: bugs here can let an action run without
a real human's approval, or let a forged receipt pass as authority. We take
reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's **[Report a vulnerability](https://github.com/countersign-labs/counter-sign/security/advisories/new)**
(the repository **Security** tab → *Advisories* → *Report a vulnerability*). This
opens a private advisory visible only to you and the maintainers.

Include, as best you can:

- the affected version, commit, or spec section;
- a description of the impact (what an attacker can do);
- steps or a minimal proof-of-concept to reproduce;
- any suggested fix.

We aim to acknowledge a report within **72 hours** and to agree on a
remediation timeline from there. We will credit reporters who wish to be named
once a fix is released.

## Supported versions

counter-sign is pre-1.0 (spec v0.1). Security fixes land on `main` and in the
latest published `0.x` release. Older `0.x` releases are not separately patched.

| Version | Supported |
| ------- | --------- |
| latest `0.x` | ✅ |
| older `0.x`  | ❌ (upgrade) |

## Scope

In scope:

- signature forgery or verification bypass (Intent, Countersignature, email link);
- authority-binding bypass (integrity accepted as authority);
- quorum bypass (one actor satisfying a multi-person quorum; timeout authorizing a quorum);
- adapter webhook authentication bypass, or message/mention injection;
- the email link flow (single-use, expiry, GET-cannot-decide) being defeated.

Out of scope:

- authority-key **distribution/pinning** — deliberately deployment policy in v0.1
  (documented in the spec and `docs/security-review.md`);
- misconfiguration explicitly warned against (e.g. `quorum > 1` with
  `default: approve`, which the library refuses to construct);
- issues in a deployer's own runtime, key custody, or hosting.

## Design notes for reviewers

The threat model and the fixes applied to date are documented in
[`docs/security-review.md`](docs/security-review.md). The spec's normative
security requirements are in `spec/countersign-spec.md` §5. Signed conformance
vectors live in [`examples/payloads/`](examples/payloads/).
