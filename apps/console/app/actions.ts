"use server";
// Server actions for the console's write path. They NEVER receive a signing key — the
// browser signs entries client-side; these actions only hand back the current head and
// validate+persist a fully-signed entry via the library's verifyChain.
import { revalidatePath } from "next/cache";
import { applySignedEntry, policyHead } from "../lib/write";

function dataDir(): string {
  return process.env.COUNTERSIGN_DATA_DIR ?? "./data";
}

/** The current policy-log head, so the client can build the next entry (seq + prev). */
export async function getHead(): Promise<{ length: number; hash: string }> {
  return policyHead(dataDir());
}

/** Validate and persist a client-signed policy entry. Revalidates the affected pages. */
export async function submitEntry(entry: unknown): Promise<{ ok: true } | { ok: false; error: string }> {
  const res = applySignedEntry(dataDir(), entry);
  if (res.ok) {
    for (const p of ["/rules", "/roles", "/admins", "/approvers", "/audit"]) revalidatePath(p);
  }
  return res;
}
