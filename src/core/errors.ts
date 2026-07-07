// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import type { Countersignature, Intent } from "./types.js";

export class CountersignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The action was not authorized: an explicit reject, or a reject Default fired. */
export class IntentRejectedError extends CountersignError {
  constructor(
    public readonly countersignature: Countersignature,
    public readonly intent: Intent,
  ) {
    super(
      `Intent ${intent.intent_id} (${intent.action}) was not authorized: ` +
        `${countersignature.decision} by ${countersignature.actor} (policy: ${countersignature.policy})`,
    );
  }
}

/** An adapter returned a Countersignature that fails verification. */
export class InvalidCountersignatureError extends CountersignError {}
