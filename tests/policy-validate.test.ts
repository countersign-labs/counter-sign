// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { validateRole, validateRule } from "../src/policy/validate.js";
import type { Role, Rule } from "../src/policy/types.js";

const role: Role = { id: "r1", org: "o1", name: "finance", members: ["m:cfo", "m:ceo"] };
const rule = (over: Partial<Rule> = {}): Rule => ({
  id: "u1", org: "o1", name: "large-refund", roles: ["r1"], quorum: 2, default: "reject", timeout_seconds: 3600, ...over,
});

describe("validateRole", () => {
  it("accepts a well-formed role", () => expect(() => validateRole(role)).not.toThrow());
  it("rejects an empty name", () => expect(() => validateRole({ ...role, name: "" })).toThrow());
  it("rejects a role with no members", () => expect(() => validateRole({ ...role, members: [] })).toThrow());
  it("rejects duplicate members (normalized)", () =>
    expect(() => validateRole({ ...role, members: ["m:cfo", "M:CFO"] })).toThrow());
});

describe("validateRule", () => {
  it("accepts a well-formed rule", () => expect(() => validateRule(rule())).not.toThrow());
  it("rejects quorum < 1 or non-integer", () => {
    expect(() => validateRule(rule({ quorum: 0 }))).toThrow();
    expect(() => validateRule(rule({ quorum: 1.5 }))).toThrow();
  });
  it("rejects quorum > 1 with default approve (timeout would bypass approvers)", () =>
    expect(() => validateRule(rule({ quorum: 2, default: "approve" }))).toThrow());
  it("accepts quorum 1 with default approve", () =>
    expect(() => validateRule(rule({ quorum: 1, default: "approve" }))).not.toThrow());
  it("rejects a timeout outside [1, 2147483]", () => {
    expect(() => validateRule(rule({ timeout_seconds: 0 }))).toThrow();
    expect(() => validateRule(rule({ timeout_seconds: 2147484 }))).toThrow();
  });
  it("rejects an empty roles list", () => expect(() => validateRule(rule({ roles: [] }))).toThrow());
});
