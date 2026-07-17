// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { CountersignError } from "../core/errors.js";
import { normalizeActor } from "../core/countersignature.js";
import type { Role, Rule } from "./types.js";

const MAX_TIMEOUT_SECONDS = 2147483; // = src/core/intent.ts
// RISK_TIERS is not exported from src/core/intent.ts — mirror the literal set here.
const RISK_TIERS = new Set(["low", "medium", "high", "critical"]);

export function validateRole(role: Role): void {
  if (!role || typeof role !== "object") throw new CountersignError("role must be an object");
  for (const f of ["id", "org", "name"] as const)
    if (typeof role[f] !== "string" || role[f].length === 0) throw new CountersignError(`role.${f} must be a non-empty string`);
  if (!Array.isArray(role.members) || role.members.length === 0)
    throw new CountersignError(`role ${role.name} must have at least one member`);
  const seen = new Set<string>();
  for (const m of role.members) {
    if (typeof m !== "string" || m.length === 0) throw new CountersignError(`role ${role.name} has an empty member`);
    const norm = normalizeActor(m);
    if (seen.has(norm)) throw new CountersignError(`role ${role.name} has a duplicate member ${m}`);
    seen.add(norm);
  }
}

export function validateRule(rule: Rule): void {
  if (!rule || typeof rule !== "object") throw new CountersignError("rule must be an object");
  for (const f of ["id", "org", "name"] as const)
    if (typeof rule[f] !== "string" || rule[f].length === 0) throw new CountersignError(`rule.${f} must be a non-empty string`);
  if (!Array.isArray(rule.roles) || rule.roles.length === 0)
    throw new CountersignError(`rule ${rule.name} must reference at least one role`);
  if (!Number.isInteger(rule.quorum) || rule.quorum < 1)
    throw new CountersignError(`rule ${rule.name}: quorum must be an integer >= 1`);
  if (rule.default !== "approve" && rule.default !== "reject")
    throw new CountersignError(`rule ${rule.name}: default must be "approve" or "reject"`);
  if (rule.quorum > 1 && rule.default === "approve")
    throw new CountersignError(`rule ${rule.name}: quorum > 1 must not combine with default: approve (a timeout would bypass required approvers)`);
  if (!Number.isInteger(rule.timeout_seconds) || rule.timeout_seconds < 1 || rule.timeout_seconds > MAX_TIMEOUT_SECONDS)
    throw new CountersignError(`rule ${rule.name}: timeout_seconds must be an integer in [1, ${MAX_TIMEOUT_SECONDS}]`);
  if (rule.risk_tier !== undefined && !RISK_TIERS.has(rule.risk_tier))
    throw new CountersignError(`rule ${rule.name}: risk_tier "${rule.risk_tier}" is not one of low|medium|high|critical`);
}
