# Contributing to Countersign

Thanks for your interest. Countersign is intentionally small — a spec plus a
reference implementation, not a framework — so contributions are held to that
bar: keep it minimal, correct, and well-tested.

## Ground rules

- **The spec is the contract.** `spec/countersign-spec.md` is normative. Code
  changes that alter behavior must match the spec; if the behavior *should*
  change, update the spec in the same PR and explain why.
- **Security-sensitive.** This is an authorization protocol. Changes to signing,
  verification, authority binding, quorum, or the adapters' webhook auth get
  extra scrutiny and must come with tests. See [SECURITY.md](SECURITY.md) for
  reporting vulnerabilities (do not open public issues for those).
- **No new runtime dependencies** without discussion. Core has zero; the only
  runtime dependency is `nodemailer` (email adapter).
- **Adapters stay dumb.** Deliver the Intent, report the decision. Policy,
  timeout/Default, and enforcement live in core.

## Development

```sh
npm install
npm run build        # tsc, must be clean
npm test             # vitest — all tests must pass
npm run gen:payloads # regenerate signed example/conformance payloads if envelopes change
```

Try it end to end with no tokens:

```sh
npm run demo:local     # you are the approver, at the terminal
npm run demo:quorum    # two-person (four-eyes) flow
npm run demo:email     # full email flow, offline
```

## Pull requests

1. Branch from `main`.
2. Keep the change focused; one concern per PR.
3. Add or update tests — new behavior needs coverage, especially security paths.
4. `npm run build && npm test` must pass locally (CI runs the same on Node 20).
5. Match the surrounding code style (TypeScript, ESM, per-file Apache header +
   SPDX line on new source files).
6. Write a clear PR description: what changed, why, and any spec impact.

## Licensing of contributions

By contributing, you agree that your code contributions are licensed under
**Apache-2.0** and any specification-text contributions under **CC BY 4.0**,
matching the repository's dual licensing. Include the Apache header on new
source files:

```ts
// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
```

## Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
