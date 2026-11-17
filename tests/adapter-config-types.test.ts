// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Source compatibility: a chat adapter config object written for 0.2.0 must
// still compile. vitest strips types without checking them, so this runs tsc
// on tests/types/adapter-config-0.2.0.ts with the project's compiler options.

import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..");
const tsc = join(root, "node_modules", ".bin", "tsc");

describe("adapter config types stay 0.2.0-compatible (F7)", () => {
  it("a full SlackConfig, TelegramConfig and WhatsAppConfig written for 0.2.0 type-checks", () => {
    let output = "";
    try {
      execFileSync(
        tsc,
        [
          "--noEmit",
          "--ignoreConfig",
          "--strict",
          "--target",
          "ES2022",
          "--module",
          "NodeNext",
          "--moduleResolution",
          "NodeNext",
          "--lib",
          "ES2022",
          "--skipLibCheck",
          "--esModuleInterop",
          "--verbatimModuleSyntax",
          "--types",
          "node",
          join(root, "tests", "types", "adapter-config-0.2.0.ts"),
        ],
        { cwd: root, encoding: "utf8", stdio: "pipe" },
      );
    } catch (err: any) {
      output = `${err.stdout ?? ""}${err.stderr ?? ""}` || String(err);
    }
    expect(output).toBe("");
  }, 60_000);
});
