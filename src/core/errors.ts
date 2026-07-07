// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see LICENSE at repo root.

import type { Countersignature, Intent, Resolution } from "./types.js";

export class CountersignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The action was not authorized: a veto, or a reject Default fired. */
export class IntentRejectedError extends CountersignError {
  /** The decisive receipt — the veto, or the timeout Default. */
  public readonly countersignature: Countersignature;

  constructor(
    public readonly resolution: Resolution,
    public readonly intent: Intent,
  ) {
    const decisive = resolution.countersignatures[resolution.countersignatures.length - 1];
    super(
      `Intent ${intent.intent_id} (${intent.action}) was not authorized: ` +
        `${resolution.decision} (policy: ${resolution.policy})` +
        (decisive ? ` by ${decisive.actor}` : ""),
    );
    this.countersignature = decisive;
  }
}

/** An adapter returned a Countersignature that fails verification. */
export class InvalidCountersignatureError extends CountersignError {}
