// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { isRenderSafeAdmin, isRenderSafeApprover, isRenderSafeRole, isRenderSafeRule } from "./schema";

describe("render-safe guards", () => {
  it("accepts well-formed records", () => {
    expect(isRenderSafeAdmin({ public_key: "k", name: "root" })).toBe(true);
    expect(isRenderSafeAdmin({ public_key: "k" })).toBe(true); // name optional
    expect(isRenderSafeRole({ id: "r", org: "o", name: "n", members: ["m:a"] })).toBe(true);
    expect(isRenderSafeRole({ id: "r", org: "o", name: "n", members: [], description: "d" })).toBe(true);
    expect(isRenderSafeRule({ id: "x", org: "o", name: "n", roles: ["r"], quorum: 1, default: "reject", timeout_seconds: 60 })).toBe(true);
    expect(isRenderSafeApprover({ actor: "m:cfo", keys: ["k1", "k2"] })).toBe(true);
  });

  it("rejects records whose displayed fields are objects (would crash React)", () => {
    expect(isRenderSafeAdmin({ public_key: "k", name: {} })).toBe(false);
    expect(isRenderSafeAdmin({ public_key: {} })).toBe(false);
    expect(isRenderSafeRole({ id: "r", org: "o", name: "n", members: ["m:a"], description: {} })).toBe(false);
    expect(isRenderSafeRole({ id: "r", org: "o", name: "n", members: [{}] })).toBe(false);
    expect(isRenderSafeRule({ id: "x", org: "o", name: "n", roles: ["r"], quorum: 1, default: "maybe", timeout_seconds: 60 })).toBe(false);
    expect(isRenderSafeRule({ id: "x", org: "o", name: "n", roles: ["r"], quorum: "1", default: "reject", timeout_seconds: 60 })).toBe(false);
    expect(isRenderSafeApprover({ actor: {}, keys: ["k"] })).toBe(false);
    expect(isRenderSafeApprover({ actor: "m", keys: [{}] })).toBe(false);
  });
});
