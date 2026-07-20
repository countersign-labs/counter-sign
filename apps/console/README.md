# @countersignlabs/console

A **local** admin console for the [counter-sign](https://www.npmjs.com/package/@countersignlabs/counter-sign) policy layer. Run your organization's signed, hash-chained policy log on your own machine — manage admin keys, roles, rules, and approvers, and read the audit trail.

Everything stays local: the console reads and writes only a data directory you point it at, and your admin signing key **never leaves the browser** (it signs each policy change client-side; the server only validates and stores).

## Run it

```sh
npx @countersignlabs/console --data-dir ./my-org --open
```

Then open http://127.0.0.1:3939 (the `--open` flag does this for you).

## Options

| Flag | Default | Description |
| --- | --- | --- |
| `--data-dir <path>` | `./data` | Directory holding `policy.jsonl`, `registry.jsonl`, `receipts.jsonl`. Created if missing. |
| `--org-key <key>` | — | Your org's public key (base64url ed25519), used to verify the approver registry. Optional; or set `COUNTERSIGN_ORG_PUBLIC_KEY`. |
| `--port <n>` | `3939` | Port to serve on. |
| `--host <addr>` | `127.0.0.1` | Address to bind. Local-only by default. |
| `--open` | — | Open the console in your browser. |
| `-h`, `--help` | — | Show help. |

## What it is

- **Self-hosted & single-org.** One console per organization, run by that org's admin. There is no central service and no login — the only authority is holding an admin ed25519 key.
- **Client-side signing.** The browser signs each policy entry; the server validates it against the library's `verifyChain` plus a fail-closed semantic gate, then persists atomically.
- **Fail-loud reads.** A broken chain or malformed record renders a prominent fault banner — never trusted, never a silent error.

## License

Apache-2.0 · © 2026 Haridarman Kumaresan
