// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { CountersignError } from "../core/errors.js";
import { normalizeActor } from "../core/countersignature.js";
import { validateRule } from "./validate.js";
import type { Approver, IntentFields } from "../core/types.js";
import type { ResolveDeps, RuleRequest } from "./types.js";

/**
 * Opt-in options for resolveRule. Omitted (or `approvers: "keyed"`), resolveRule
 * behaves exactly as it always has.
 */
export interface ResolveOptions {
  /**
   * How role members become approvers.
   * - `"keyed"` (the default): each member is bound to their one ACTIVE registry key.
   * - `"vouched"`: each member becomes a `vouched` approver, the form the chat and
   *   email adapters (button-webhook / link-callback) accept. No key is looked up and
   *   no registry is needed. A vouched slot is only allowed at quorum 1 (spec §1
   *   "Trust model"), so a rule with any other quorum is refused, never downgraded.
   */
  approvers?: "keyed" | "vouched";
  /**
   * Vouched mode only: keep just the members whose actor is on this channel
   * (`<channel>:<address>`), e.g. `"slack"` for a SlackAdapter that can only ever
   * hear Slack users. Filtering can only narrow who may approve; if no member is
   * left the call is refused.
   */
  channel?: string;
}

/** Dependencies for vouched resolution: the registry is not consulted. */
export type VouchedResolveDeps = Omit<ResolveDeps, "registry"> & { registry?: ResolveDeps["registry"] };

/**
 * Resolve a named rule into IntentFields for createIntent. The rule supplies the POLICY
 * (which roles approve, quorum, default, timeout); the request supplies the concrete
 * action context (summary, and optionally action/risk_tier overrides). Roles are expanded
 * into keyed approvers by looking each member's ACTIVE bound key up from the registry, so
 * a member with no active enrollment fails closed. Pure; never mints an Intent itself.
 *
 * Pass `{ approvers: "vouched" }` to resolve a quorum-1 rule into vouched approvers for a
 * chat or email adapter instead (see ResolveOptions).
 */
export function resolveRule(ruleName: string, request: RuleRequest, deps: ResolveDeps, options?: { approvers?: "keyed" }): IntentFields;
export function resolveRule(
  ruleName: string,
  request: RuleRequest,
  deps: VouchedResolveDeps,
  options: { approvers: "vouched"; channel?: string },
): IntentFields;
export function resolveRule(ruleName: string, request: RuleRequest, deps: ResolveDeps, options?: ResolveOptions): IntentFields;
export function resolveRule(ruleName: string, request: RuleRequest, deps: VouchedResolveDeps, options: ResolveOptions = {}): IntentFields {
  const mode = options.approvers ?? "keyed";
  if (mode !== "keyed" && mode !== "vouched")
    throw new CountersignError(`options.approvers must be "keyed" or "vouched", got ${JSON.stringify(options.approvers)}`);
  if (options.channel !== undefined && mode !== "vouched")
    throw new CountersignError('options.channel applies only with { approvers: "vouched" }');
  if (options.channel !== undefined && (typeof options.channel !== "string" || options.channel.length === 0 || options.channel.includes(":")))
    throw new CountersignError(`options.channel must be a bare channel name such as "slack", got ${JSON.stringify(options.channel)}`);

  if (!deps.store.verify())
    throw new CountersignError("policy store failed chain verification — refusing to resolve a rule from an unverified or tampered policy log");

  const rule = deps.store.getRule(deps.org, ruleName);
  if (!rule) throw new CountersignError(`no rule named "${ruleName}" for org ${deps.org}`);
  validateRule(rule);
  // Refuse before anything else: a vouched slot is server-forgeable, so it can never
  // fill a multi-person quorum. Downgrading the quorum would silently weaken the rule.
  if (mode === "vouched" && rule.quorum !== 1)
    throw new CountersignError(
      `rule "${ruleName}" has quorum ${rule.quorum}; vouched (chat) approvers are allowed only at quorum 1 — resolve it with keyed approvers instead`,
    );

  const memberActors = new Set<string>();
  for (const roleId of rule.roles) {
    const role = deps.store.getRoleById(deps.org, roleId);
    if (!role) throw new CountersignError(`rule "${ruleName}" references unknown role ${roleId}`);
    for (const m of role.members) memberActors.add(normalizeActor(m));
  }
  if (memberActors.size === 0) throw new CountersignError(`rule "${ruleName}" resolves to zero approvers`);
  if (memberActors.size < rule.quorum)
    throw new CountersignError(`rule "${ruleName}" needs quorum ${rule.quorum} but only ${memberActors.size} distinct approver(s) are available`);

  const approvers: Approver[] = [];
  if (mode === "vouched") {
    const prefix = options.channel === undefined ? undefined : `${normalizeActor(options.channel)}:`;
    for (const actor of memberActors) {
      if (prefix === undefined || actor.startsWith(prefix)) approvers.push({ actor, mode: "vouched" });
    }
    if (approvers.length === 0)
      throw new CountersignError(`rule "${ruleName}" has no member on channel ${options.channel}`);
  } else {
    if (!deps.registry)
      throw new CountersignError(`resolving rule "${ruleName}" to keyed approvers needs deps.registry (or pass { approvers: "vouched" })`);
    const active = deps.registry.activeKeyMap();
    for (const actor of memberActors) {
      const keys = active.get(actor);
      if (!keys || keys.size === 0) throw new CountersignError(`approver ${actor} has no active enrolled key`);
      if (keys.size > 1) throw new CountersignError(`approver ${actor} has multiple active keys; policy resolution requires exactly one (rotate/revoke to disambiguate)`);
      approvers.push({ actor, mode: "keyed", public_key: [...keys][0] });
    }
  }

  const action = request.action ?? rule.action;
  if (!action) throw new CountersignError(`rule "${ruleName}" has no action and the request supplied none`);
  const risk_tier = request.risk_tier ?? rule.risk_tier;
  if (!risk_tier) throw new CountersignError(`rule "${ruleName}" has no risk_tier and the request supplied none`);
  if (!request.summary) throw new CountersignError("request.summary is required");

  return { action, summary: request.summary, risk_tier, approvers, quorum: rule.quorum, timeout: rule.timeout_seconds, default: rule.default };
}
