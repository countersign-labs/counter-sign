// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// No-network demo: the approver is you, at this terminal. No tokens needed.
//   npm run demo:local

import { LocalAdapter } from "../src/adapters/local.js";
import { demoFields, runDemo } from "./_shared.js";

await runDemo(new LocalAdapter(), demoFields({ approvers: ["local:you"] }));
