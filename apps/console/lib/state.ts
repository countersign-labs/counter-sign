// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
import { loadConsoleState, type ConsoleState } from "./store";

/** Resolve the data dir + org key from env and load the verified console state.
 *  COUNTERSIGN_DATA_DIR (default ./data) and COUNTERSIGN_ORG_PUBLIC_KEY. */
export function getState(): ConsoleState {
  const dataDir = process.env.COUNTERSIGN_DATA_DIR ?? "./data";
  const orgKey = process.env.COUNTERSIGN_ORG_PUBLIC_KEY ?? "";
  return loadConsoleState(dataDir, orgKey);
}
