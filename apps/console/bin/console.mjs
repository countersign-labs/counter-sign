#!/usr/bin/env node
// counter-sign console — a LOCAL admin console for an org's signed policy log.
// Runs a self-contained Next server (bundled at .next/standalone) against a local data
// directory. Nothing leaves the machine: the console reads/writes only the data dir, and
// the admin's signing key never leaves the browser.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const argv = process.argv.slice(2);

/** Read `--name value` (or a bare `--name` flag). */
function opt(name, def) {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = argv[i + 1];
  return v && !v.startsWith("--") ? v : true;
}

if (argv.includes("--help") || argv.includes("-h")) {
  process.stdout.write(`
  counter-sign console — a local admin console for your org's signed policy log.

  Usage:
    npx @countersignlabs/console [options]

  Options:
    --data-dir <path>   Directory holding policy.jsonl / registry.jsonl / receipts.jsonl
                        (default: ./data). Created if missing.
    --org-key <key>     Your org's public key (base64url ed25519), used to verify the
                        approver registry. Optional (or set COUNTERSIGN_ORG_PUBLIC_KEY).
    --port <n>          Port to serve on (default: 3939).
    --host <addr>       Address to bind (default: 127.0.0.1 — local only).
    --open              Open the console in your browser.
    -h, --help          Show this help.

  Everything stays on your machine: the console reads/writes only the data directory,
  and your admin key never leaves the browser.

`);
  process.exit(0);
}

const dataDir = resolve(process.cwd(), String(opt("data-dir", process.env.COUNTERSIGN_DATA_DIR || "./data")));
const orgKeyRaw = opt("org-key", process.env.COUNTERSIGN_ORG_PUBLIC_KEY || "");
const orgKey = orgKeyRaw === true ? "" : String(orgKeyRaw);
const port = String(opt("port", process.env.PORT || "3939"));
const host = String(opt("host", "127.0.0.1"));
const openBrowser = argv.includes("--open");

const server = join(pkgRoot, ".next", "standalone", "server.js");
if (!existsSync(server)) {
  process.stderr.write("counter-sign console: bundled server is missing (.next/standalone/server.js) — the package was not built correctly. Please report this.\n");
  process.exit(1);
}

// The data dir is the admin's — create it if new so a first run just works.
try {
  mkdirSync(dataDir, { recursive: true });
} catch {
  /* best effort */
}

process.stdout.write(
  `\n  counter-sign console\n` +
    `  data dir : ${dataDir}\n` +
    `  org key  : ${orgKey ? orgKey.slice(0, 12) + "…" : "(not set — approver-registry verification disabled)"}\n` +
    `  serving  : http://${host}:${port}\n\n`,
);

const child = spawn(process.execPath, [server], {
  stdio: "inherit",
  env: {
    ...process.env,
    COUNTERSIGN_DATA_DIR: dataDir,
    COUNTERSIGN_ORG_PUBLIC_KEY: orgKey,
    PORT: port,
    HOSTNAME: host,
  },
});

child.on("exit", (code) => process.exit(code ?? 0));
process.on("SIGINT", () => child.kill("SIGINT"));
process.on("SIGTERM", () => child.kill("SIGTERM"));

if (openBrowser) {
  const url = `http://${host}:${port}`;
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  setTimeout(() => {
    try {
      spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
    } catch {
      /* ignore */
    }
  }, 1500);
}
