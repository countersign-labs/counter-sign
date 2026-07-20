// Make Next's standalone output self-contained: copy the hashed static assets and the public/
// dir into it, so shipping only `.next/standalone` and running `node server.js` serves everything.
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url))); // apps/console
const standalone = join(root, ".next", "standalone");
if (!existsSync(standalone)) {
  console.error("postbuild: .next/standalone not found — run `next build` with output:'standalone' first.");
  process.exit(1);
}

const staticSrc = join(root, ".next", "static");
if (existsSync(staticSrc)) {
  mkdirSync(join(standalone, ".next"), { recursive: true });
  cpSync(staticSrc, join(standalone, ".next", "static"), { recursive: true });
}

const publicSrc = join(root, "public");
if (existsSync(publicSrc)) {
  cpSync(publicSrc, join(standalone, "public"), { recursive: true });
}

console.log("postbuild: standalone is self-contained (static + public copied in).");
