import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const rootDir = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Self-contained server so `npx @countersignlabs/console` runs without installing Next's full
  // dependency tree — everything it needs is traced into .next/standalone.
  output: "standalone",
  // Scope file tracing to the console (avoids the repo's multi-lockfile ambiguity and the
  // monorepo-root nesting), so the entry is a predictable .next/standalone/server.js.
  outputFileTracingRoot: rootDir,
  transpilePackages: ["@countersignlabs/counter-sign"],
};

export default nextConfig;
