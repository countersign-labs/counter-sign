// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// Prints a fresh ed25519 keypair for use as COUNTERSIGN_AUTHORITY_KEY.

import { generateKeypair } from "../src/core/keys.js";

const kp = generateKeypair();
console.log(`COUNTERSIGN_AUTHORITY_KEY=${kp.secretKey}`);
console.log(`# corresponding public key (share freely): ${kp.publicKey}`);
