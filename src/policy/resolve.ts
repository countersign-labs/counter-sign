// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { CountersignError } from "../core/errors.js";
import { normalizeActor } from "../core/countersignature.js";
import { validateRule } from "./validate.js";
import type { Approver, IntentFields } from "../core/types.js";
import type { ResolveDeps, RuleRequest } from "./types.js";

/**
 * Resolve a named rule into IntentFields for createIntent. The rule supplies the POLICY
 * (which roles approve, quorum, default, timeout); the request supplies the concrete
 * action context (summary, and optionally action/risk_tier overrides). Roles are expanded
 * into keyed approvers by looking each member's ACTIVE bound key up from the registry, so
 * a member with no active enrollment fails closed. Pure; never mints an Intent itself.
 */
export function resolveRule(ruleName: string, request: RuleRequest, deps: ResolveDeps): IntentFields {
  if (!deps.store.verify())
    throw new CountersignError("policy store failed chain verification — refusing to resolve a rule from an unverified or tampered policy log");

  const rule = deps.store.getRule(deps.org, ruleName);
  if (!rule) throw new CountersignError(`no rule named "${ruleName}" for org ${deps.org}`);
  validateRule(rule);

  const memberActors = new Set<string>();
  for (const roleId of rule.roles) {
    const role = deps.store.getRoleById(deps.org, roleId);
    if (!role) throw new CountersignError(`rule "${ruleName}" references unknown role ${roleId}`);
    for (const m of role.members) memberActors.add(normalizeActor(m));
  }
  if (memberActors.size === 0) throw new CountersignError(`rule "${ruleName}" resolves to zero approvers`);
  if (memberActors.size < rule.quorum)
    throw new CountersignError(`rule "${ruleName}" needs quorum ${rule.quorum} but only ${memberActors.size} distinct approver(s) are available`);

  const active = deps.registry.activeKeyMap();
  const approvers: Approver[] = [];
  for (const actor of memberActors) {
    const keys = active.get(actor);
    if (!keys || keys.size === 0) throw new CountersignError(`approver ${actor} has no active enrolled key`);
    if (keys.size > 1) throw new CountersignError(`approver ${actor} has multiple active keys; policy resolution requires exactly one (rotate/revoke to disambiguate)`);
    approvers.push({ actor, mode: "keyed", public_key: [...keys][0] });
  }

  const action = request.action ?? rule.action;
  if (!action) throw new CountersignError(`rule "${ruleName}" has no action and the request supplied none`);
  const risk_tier = request.risk_tier ?? rule.risk_tier;
  if (!risk_tier) throw new CountersignError(`rule "${ruleName}" has no risk_tier and the request supplied none`);
  if (!request.summary) throw new CountersignError("request.summary is required");

  return { action, summary: request.summary, risk_tier, approvers, quorum: rule.quorum, timeout: rule.timeout_seconds, default: rule.default };
}
