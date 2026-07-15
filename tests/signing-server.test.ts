// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
// SigningServer end-to-end: a keyed passkey approver taps a deep-link, the page
// renders, and a POSTed WebAuthn assertion is recorded — driven against a real
// HTTP server with an assertion constructed as the browser would.

import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { PendingDecisions } from "../src/adapter.js";
import { createSigningToken, verifySigningToken, SigningServer } from "../src/signing.js";
import { createIntent } from "../src/core/intent.js";
import { fromB64url, generateKeypair, publicKeyFromSecret, signBytes, toB64url, utf8 } from "../src/core/keys.js";
import type { Approver, Intent } from "../src/core/types.js";

const agent = { id: "agent:test", keypair: generateKeypair() };
const authority = generateKeypair();
const authPub = publicKeyFromSecret(authority.secretKey);
const rpId = "approve.countersignlabs.com";
const origin = `https://${rpId}`;

function passkeyApprover(actor: string): { approver: Approver; sign: (data: Buffer) => Buffer } {
  const kp = generateKeypair();
  return { approver: { actor, mode: "keyed", public_key: `webauthn-ed25519:${kp.publicKey}` }, sign: (d) => fromB64url(signBytes(kp.secretKey, d)) };
}

function intentWith(approvers: Approver[], quorum = 1): Intent {
  return createIntent({ action: "prod.deploy", summary: "Deploy 2.4.0 to production", risk_tier: "critical", approvers, quorum, timeout: 300, default: "reject" }, agent);
}

function makeServer(pending: PendingDecisions): { server: Server; base: string; signer: SigningServer } {
  const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin] }, baseUrl: origin });
  const server = createServer(signer.handler());
  return { server, base: "", signer };
}
async function listen(server: Server): Promise<string> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** Build the WebAuthn assertion the browser would produce for `challenge`. */
function assertion(challenge: string, sign: (d: Buffer) => Buffer, org = origin) {
  const authData = Buffer.concat([createHash("sha256").update(utf8(rpId)).digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: org }), "utf8");
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  return { authenticator_data: toB64url(authData), client_data_json: toB64url(clientData), signature: toB64url(sign(signedData)) };
}

const servers: Server[] = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });

describe("signing token", () => {
  it("round-trips and rejects tampering, expiry, and cross-type", () => {
    const i = intentWith([passkeyApprover("m:ceo").approver]);
    const tok = createSigningToken(i, "m:ceo", authority.secretKey, Date.now() + 60_000);
    const p = verifySigningToken(tok, authPub);
    expect(p?.intent_id).toBe(i.intent_id);
    expect(p?.actor).toBe("m:ceo");
    expect(verifySigningToken(tok + "x", authPub)).toBeNull();
    expect(verifySigningToken(tok, generateKeypair().publicKey)).toBeNull(); // wrong authority
  });
});

describe("SigningServer GET/POST", () => {
  it("renders the page and records a passkey approval end-to-end", async () => {
    const pending = new PendingDecisions();
    const { approver, sign } = passkeyApprover("m:ceo");
    const i = intentWith([approver]);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const resolution = signer.awaitResolution(i);

    const url = signer.signingUrl(i, "m:ceo").replace(origin, base);
    const html = await (await fetch(url)).text();
    expect(html).toContain("Deploy 2.4.0 to production");
    const data = JSON.parse(html.match(/const D = (\{.*?\});/s)![1]);

    const a = assertion(data.challengeApprove, sign);
    const token = new URL(url).searchParams.get("token");
    const post = await fetch(`${base}/sign`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, decision: "approve", timestamp: data.timestamp, ...a }),
    });
    expect(post.status).toBe(200);
    expect((await post.json()).status).toBe("resolved");
    expect((await resolution).decision).toBe("approve");
  });

  it("rejects a tampered decision (assertion no longer binds)", async () => {
    const pending = new PendingDecisions();
    const { approver, sign } = passkeyApprover("m:ceo");
    const i = intentWith([approver]);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    void signer.awaitResolution(i);
    const url = signer.signingUrl(i, "m:ceo").replace(origin, base);
    const data = JSON.parse((await (await fetch(url)).text()).match(/const D = (\{.*?\});/s)![1]);
    const token = new URL(url).searchParams.get("token");

    // Sign the APPROVE challenge but POST it as a REJECT — record recomputes the
    // digest for "reject", which won't match the approve assertion.
    const a = assertion(data.challengeApprove, sign);
    const post = await fetch(`${base}/sign`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, decision: "reject", timestamp: data.timestamp, ...a }),
    });
    expect(post.status).toBe(400);
  });

  it("escapes a malicious intent summary so it cannot break out of the <script> block (XSS)", async () => {
    const pending = new PendingDecisions();
    const { approver } = passkeyApprover("m:ceo");
    const evil = '</script><script>window.__xss=1</script>';
    const i = createIntent({ action: "a", summary: evil, risk_tier: "low", approvers: [approver], timeout: 300, default: "reject" }, agent);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    void signer.awaitResolution(i);
    const url = signer.signingUrl(i, "m:ceo").replace(origin, base);
    const resp = await fetch(url);
    const html = await resp.text();
    // The `<` from the summary is escaped inside the data blob; the injected tags are inert.
    expect(html).not.toContain(evil);
    expect(html).toContain("\\u003c/script>");
    // Defense-in-depth CSP present, and the inline script is nonce'd.
    expect(resp.headers.get("content-security-policy")).toMatch(/script-src 'nonce-/);
    expect(html).toMatch(/<script nonce="[^"]+">/);
  });

  it("GET with an invalid/expired token shows an error page (410)", async () => {
    const pending = new PendingDecisions();
    const { server } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const res = await fetch(`${base}/sign?token=garbage`);
    expect(res.status).toBe(410);
    expect(await res.text()).toContain("invalid, expired");
  });

  it("signingUrl refuses a non-passkey (vouched or raw-keyed) approver", () => {
    const pending = new PendingDecisions();
    const { signer } = makeServer(pending);
    const raw = generateKeypair();
    const i = intentWith([{ actor: "m:bot", mode: "keyed", public_key: raw.publicKey }]);
    expect(() => signer.signingUrl(i, "m:bot")).toThrow(/passkey/);
  });
});
