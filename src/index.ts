// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

export * from "./core/index.js";
export {
  type Adapter,
  type SettleResult,
  type PendingDecisionsOptions,
  type PendingDecisionsSource,
  PendingDecisions,
  pendingDecisionsFor,
  DeliveryPartialError,
  assertVouchedApprovers,
  requireEnv,
  authorityKeyFromEnv,
  parseDecisionPayload,
  decisionPayload,
  formatIntent,
  readBody,
} from "./adapter.js";
export { wrapAction, type WrapOptions } from "./shim.js";
export {
  SigningServer,
  createSigningToken,
  verifySigningToken,
  type SigningServerConfig,
} from "./signing.js";
export {
  SigningLinkAdapter,
  type SigningLink,
  type SigningLinkAdapterConfig,
} from "./adapters/signing-link.js";
export {
  ApproverRegistry,
  createEnrollmentProof,
  enrollmentChallenge,
  assertApproversEnrolled,
  type EnrollmentRecord,
  type RegistryHead,
  type PasskeyEnrollmentProof,
} from "./registry.js";
export {
  ReceiptLog,
  FileIntentStore,
  type IntentStore,
  type ReceiptLogOptions,
  type ReceiptSink,
  type ReceiptLogReport,
  type ReceiptFault,
  type TornTailReport,
  type VerifyAllOptions,
  type ChainEntry,
  type ChainHead,
  type ChainReport,
} from "./receipt-log.js";
export type { TornTail, QuarantineRecord } from "./durable-file.js";
export {
  DurableDecisions,
  FilePendingStore,
  type FilePendingStoreOptions,
  type LockStep,
  type PendingStore,
  type PendingRecord,
  type PendingStatus,
  type DurableDecisionsOptions,
  type RestoreOptions,
  type RestoreReport,
} from "./resumable.js";
export * from "./policy/index.js";
