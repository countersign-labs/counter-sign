// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..");
const load = (p: string) => JSON.parse(readFileSync(join(root, p), "utf8"));

const ajv = new Ajv2020.default({ strict: true, allErrors: true });
addFormats.default(ajv);
const validateIntent = ajv.compile(load("schemas/intent.schema.json"));
const validateCountersignature = ajv.compile(load("schemas/countersignature.schema.json"));

const payloadDir = join(root, "examples", "payloads");
const payloadFiles = readdirSync(payloadDir).filter((f) => f.endsWith(".json"));

describe("JSON Schemas (draft 2020-12) validate every example payload", () => {
  it("has example payloads to validate", () => {
    expect(payloadFiles.some((f) => f.includes("intent"))).toBe(true);
    expect(payloadFiles.some((f) => f.includes("countersignature"))).toBe(true);
  });

  for (const file of payloadFiles) {
    it(`validates examples/payloads/${file}`, () => {
      const data = load(join("examples", "payloads", file));
      const validate = file.includes("countersignature") ? validateCountersignature : validateIntent;
      const valid = validate(data);
      expect(validate.errors ?? []).toEqual([]);
      expect(valid).toBe(true);
    });
  }

  it("rejects an intent with a missing default", () => {
    const intent = load("examples/payloads/intent.example.json");
    delete intent.default;
    expect(validateIntent(intent)).toBe(false);
  });

  it("rejects a countersignature with an invented decision", () => {
    const cs = load("examples/payloads/countersignature.approve.example.json");
    cs.decision = "maybe";
    expect(validateCountersignature(cs)).toBe(false);
  });

  it("rejects unknown extra fields on both envelopes", () => {
    const intent = load("examples/payloads/intent.example.json");
    intent.extra = true;
    expect(validateIntent(intent)).toBe(false);
    const cs = load("examples/payloads/countersignature.approve.example.json");
    cs.extra = true;
    expect(validateCountersignature(cs)).toBe(false);
  });
});
