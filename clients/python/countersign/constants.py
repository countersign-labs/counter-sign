# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""Protocol constants — kept in lockstep with the TypeScript reference (types.ts)."""

COUNTERSIGN_VERSION = "0.2"

# Signature domain-separation contexts. Each artifact type signs under a distinct
# label so a signature minted for one envelope can never be replayed as another.
INTENT_CONTEXT = "countersign-intent-v0.2"
COUNTERSIGNATURE_CONTEXT = "countersign-countersignature-v0.2"
LINK_CONTEXT = "countersign-link-v0.2"

# The receipt chain's genesis prev: a fixed, version-domain-separated anchor.
CHAIN_GENESIS_LABEL = "countersign-receipt-chain-v0.1"

# Reserved actor for the runtime timeout Default; never a real approver.
DEFAULT_TIMEOUT_ACTOR = "default:timeout"

RISK_TIERS = frozenset({"low", "medium", "high", "critical"})
DECISIONS = frozenset({"approve", "reject"})
APPROVER_MODES = frozenset({"vouched", "keyed"})

# floor((2**31 - 1) / 1000): largest timeout whose ms value a JS setTimeout won't clamp.
MAX_TIMEOUT_SECONDS = 2147483
