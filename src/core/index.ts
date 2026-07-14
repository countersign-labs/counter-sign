// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

export * from "./types.js";
export * from "./errors.js";
export { canonicalize } from "./canonical.js";
export {
  generateKeypair,
  publicKeyFromSecret,
  signBytes,
  verifyBytes,
  verifyRaw,
  toB64url,
  fromB64url,
  hexToBytes,
  utf8,
  type Keypair,
} from "./keys.js";
export { createIntent, verifyIntent, quorumOf, assertIntentInvariants, type AgentIdentity } from "./intent.js";
export { signDecision, verifyCountersignature, normalizeActor, type VerifyOptions } from "./countersignature.js";
export { deadline, isExpired, defaultResolution, verifyResolution, awaitWithDefault } from "./defaults.js";
