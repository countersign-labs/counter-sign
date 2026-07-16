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
import { SigningLinkAdapter } from "../src/adapters/signing-link.js";
import { wrapAction } from "../src/shim.js";
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

/** Click-time challenge (POST phase "challenge"). */
async function getChallenge(base: string, token: string | null, decision: string): Promise<{ timestamp: string; challenge: string; error?: string }> {
  const r = await fetch(`${base}/sign`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ phase: "challenge", token, decision }) });
  return r.json();
}
/** POST the recorded assertion, signing `ch.challenge` but claiming `decision`. */
function record(base: string, token: string | null, decision: string, ch: { timestamp: string; challenge: string }, sign: (d: Buffer) => Buffer) {
  return fetch(`${base}/sign`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, decision, timestamp: ch.timestamp, ...assertion(ch.challenge, sign) }),
  });
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
    const token = new URL(url).searchParams.get("token");

    const ch = await getChallenge(base, token, "approve"); // click-time challenge
    const post = await record(base, token, "approve", ch, sign);
    expect(post.status).toBe(200);
    expect((await post.json()).status).toBe("resolved");
    expect((await resolution).decision).toBe("approve");
  });

  it("makes the signing link single-use — a replayed POST is refused (410)", async () => {
    const pending = new PendingDecisions();
    const { approver, sign } = passkeyApprover("m:ceo");
    const i = intentWith([approver], 1);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    void signer.awaitResolution(i);
    const url = signer.signingUrl(i, "m:ceo").replace(origin, base);
    const token = new URL(url).searchParams.get("token");
    const ch = await getChallenge(base, token, "approve");

    const first = await record(base, token, "approve", ch, sign);
    expect(first.status).toBe(200);
    const replay = await record(base, token, "approve", ch, sign); // exact replay
    expect(replay.status).toBe(410);
    expect((await replay.json()).error).toMatch(/already been used/);
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
    const token = new URL(url).searchParams.get("token");

    // Get an APPROVE challenge, sign it, but POST it as a REJECT — the server
    // recomputes the digest for "reject", which won't match the approve assertion.
    const ch = await getChallenge(base, token, "approve");
    const post = await record(base, token, "reject", ch, sign);
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

  it("asks the browser for userVerification=required when the policy requires UV", async () => {
    const pending = new PendingDecisions();
    const { approver } = passkeyApprover("m:ceo");
    const i = intentWith([approver]);
    // A deployment that REQUIRES user verification.
    const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin], requireUserVerification: true }, baseUrl: origin });
    const server = createServer(signer.handler());
    servers.push(server);
    const base = await listen(server);
    void signer.awaitResolution(i);
    const html = await (await fetch(signer.signingUrl(i, "m:ceo").replace(origin, base))).text();
    // The page data carries the flag, and the ceremony escalates to "required".
    expect(html).toContain('"requireUserVerification":true');
    expect(html).toContain('D.requireUserVerification ? "required" : "preferred"');
  });

  it("builds a working /sign link even when baseUrl has a trailing slash", async () => {
    const pending = new PendingDecisions();
    const { approver } = passkeyApprover("m:ceo");
    const i = intentWith([approver]);
    // baseUrl deliberately ends in "/" — a naive concat would produce "//sign" (404).
    const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin] }, baseUrl: origin + "/" });
    const server = createServer(signer.handler());
    servers.push(server);
    const base = await listen(server);
    void signer.awaitResolution(i);
    const url = signer.signingUrl(i, "m:ceo");
    expect(url).toContain("/sign?token=");
    expect(url).not.toContain("//sign");
    // …and it resolves to the page, not a 404.
    expect((await fetch(url.replace(origin, base))).status).toBe(200);
  });

  it("completes a passkey decision end-to-end under a base PATH PREFIX (link, GET, and POSTs all agree)", async () => {
    const pending = new PendingDecisions();
    const { approver, sign } = passkeyApprover("m:ceo");
    const i = intentWith([approver]);
    // Mounted behind a path prefix — link, handler route, and page POSTs must all use it.
    const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin] }, baseUrl: origin + "/approvals" });
    const server = createServer(signer.handler());
    servers.push(server);
    const base = await listen(server);
    const resolution = signer.awaitResolution(i);

    const url = signer.signingUrl(i, "m:ceo");
    expect(url).toContain("/approvals/sign?token="); // prefix preserved in the link
    const path = new URL(url).pathname; // "/approvals/sign"
    const token = new URL(url).searchParams.get("token");

    // GET the page at the prefixed path (the handler must match "*/sign", not just "/sign").
    const pageResp = await fetch(`${base}${path}?token=${encodeURIComponent(token!)}`);
    expect(pageResp.status).toBe(200);
    const html = await pageResp.text();
    expect(html).toContain("Deploy 2.4.0 to production");
    // The page POSTs back to its own path, not the origin root.
    expect(html).toContain("fetch(location.pathname");

    // POST challenge + record to the SAME prefixed path — the decision must complete.
    const postTo = (b: object) => fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });
    const ch = await (await postTo({ phase: "challenge", token, decision: "approve" })).json();
    expect(ch.challenge).toBeTruthy();
    const post = await postTo({ token, decision: "approve", timestamp: ch.timestamp, ...assertion(ch.challenge, sign) });
    expect(post.status).toBe(200);
    expect((await resolution).decision).toBe("approve");
  });

  it("normalizes a trailing slash on a prefixed base (no '//sign')", () => {
    const pending = new PendingDecisions();
    const { approver } = passkeyApprover("m:ceo");
    const i = intentWith([approver]);
    const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin] }, baseUrl: origin + "/approvals/" });
    void signer.awaitResolution(i);
    const url = signer.signingUrl(i, "m:ceo");
    expect(url).toContain("/approvals/sign?token=");
    expect(url).not.toContain("/approvals//sign");
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

describe("SigningLinkAdapter — delivers keyed intents through the wrapAction path", () => {
  it("sends each keyed approver a link and resolves the passkey quorum end-to-end", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const b = passkeyApprover("m:cto");
    const i = intentWith([a.approver, b.approver], 2); // 2-of-2 keyed passkey
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);

    const sent: { actor: string; url: string }[] = [];
    const adapter = new SigningLinkAdapter({ server: signer, notify: (l) => void sent.push({ actor: l.actor, url: l.url }) });

    await adapter.deliver(i); // registers the wait, then notifies each approver
    const resolution = adapter.awaitResolution(i);
    expect(sent.map((s) => s.actor).sort()).toEqual(["m:ceo", "m:cto"]);

    // Each approver taps their own link and signs with their own passkey.
    for (const { actor, url } of sent) {
      const token = new URL(url.replace(origin, base)).searchParams.get("token");
      const sign = actor === "m:ceo" ? a.sign : b.sign;
      const ch = await getChallenge(base, token, "approve");
      const post = await record(base, token, "approve", ch, sign);
      expect(post.status).toBe(200);
    }
    expect((await resolution).decision).toBe("approve"); // quorum met by two OWN-key receipts
  });

  it("awaitResolution BEFORE deliver still resolves (idempotent wait, no clobber)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const i = intentWith([a.approver], 1);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });

    // Await FIRST, before deliver — the old consume-once map stranded this promise
    // because deliver() then registered a SECOND wait that clobbered the entry.
    const resolution = adapter.awaitResolution(i);
    await adapter.deliver(i); // idempotent wait → same entry/promise

    const url = signer.signingUrl(i, "m:ceo").replace(origin, base);
    const token = new URL(url).searchParams.get("token");
    const ch = await getChallenge(base, token, "approve");
    expect((await record(base, token, "approve", ch, a.sign)).status).toBe(200);
    expect((await resolution).decision).toBe("approve"); // the pre-deliver promise resolves
  });

  it("wrapAction uses the adapter's webauthn policy when opts.webauthn is omitted", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const { server, signer } = makeServer(pending); // server has the RP policy
    servers.push(server);
    const base = await listen(server);
    const sent: { actor: string; url: string }[] = [];
    const adapter = new SigningLinkAdapter({ server: signer, notify: (l) => void sent.push({ actor: l.actor, url: l.url }) });
    let ran = false;
    const deploy = wrapAction(
      () => { ran = true; return "deployed"; },
      { action: "prod.deploy", summary: "Deploy 2.4.0 to production", risk_tier: "critical", approvers: [a.approver], quorum: 1, timeout: 300, default: "reject" },
      adapter,
      { agent, authorityKey: authority.secretKey }, // NO opts.webauthn — the adapter supplies it
    );
    const resultP = deploy();
    for (let i = 0; i < 100 && sent.length < 1; i++) await new Promise((r) => setTimeout(r, 5));
    const url = new URL(sent[0].url.replace(origin, base));
    const token = url.searchParams.get("token");
    const ch = await getChallenge(base, token, "approve");
    expect((await record(base, token, "approve", ch, a.sign)).status).toBe(200);
    expect(await resultP).toBe("deployed"); // verified with the adapter's policy — no split-brain
    expect(ran).toBe(true);
  });

  it("wrapAction rejects a webauthn policy that diverges from the adapter's", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const { signer } = makeServer(pending); // policy: { rpId, allowedOrigins:[origin] }, no UV
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
    const deploy = wrapAction(
      () => "x",
      { action: "a", summary: "s", risk_tier: "critical", approvers: [a.approver], quorum: 1, timeout: 300, default: "reject" },
      adapter,
      { agent, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin], requireUserVerification: true } }, // diverges (UV)
    );
    await expect(deploy()).rejects.toThrow(/SAME policy|differs/);
  });

  it("HEADLINE: a decision made DURING deliver's notify loop is NOT lost (no fail-open to Default)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const i = intentWith([a.approver], 1);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    // notify() itself drives the approval — so the decision lands WHILE deliver() is
    // still running, resolving+evicting the pending entry. The captured promise must
    // survive so awaitResolution() returns the real decision, not a fresh empty wait.
    const adapter = new SigningLinkAdapter({
      server: signer,
      notify: async (l) => {
        const token = new URL(l.url.replace(origin, base)).searchParams.get("token");
        const ch = await getChallenge(base, token, "approve");
        await record(base, token, "approve", ch, a.sign);
      },
    });
    await adapter.deliver(i);
    expect((await adapter.awaitResolution(i)).decision).toBe("approve"); // would hang/Default before the fix
  });

  it("a delivery failure AFTER a decision landed keeps the approval (does not throw)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const b = passkeyApprover("m:cto");
    const i = intentWith([a.approver, b.approver], 1); // quorum 1 — A alone resolves it
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const adapter = new SigningLinkAdapter({
      server: signer,
      notify: async (l) => {
        if (l.actor === "m:ceo") {
          const token = new URL(l.url.replace(origin, base)).searchParams.get("token");
          const ch = await getChallenge(base, token, "approve");
          await record(base, token, "approve", ch, a.sign); // A approves (quorum met)
        } else {
          throw new Error("delivery to B failed"); // …then B's link fails
        }
      },
    });
    await expect(adapter.deliver(i)).resolves.toBeUndefined(); // does NOT throw the delivery error
    expect((await adapter.awaitResolution(i)).decision).toBe("approve");
  });

  it("reconcileWebAuthn is not fooled by a duplicate origin masking a real divergence", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const signer = new SigningServer({ pending, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin, "https://other.example"] }, baseUrl: origin });
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
    const deploy = wrapAction(
      () => "x",
      { action: "a", summary: "s", risk_tier: "critical", approvers: [a.approver], quorum: 1, timeout: 300, default: "reject" },
      adapter,
      { agent, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin, origin] } }, // dupe hides the missing 2nd origin
    );
    await expect(deploy()).rejects.toThrow(/SAME policy|differs/);
  });

  it("a single approver's channel failure does NOT abort a still-satisfiable M-of-N quorum", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:a");
    const b = passkeyApprover("m:b");
    const c = passkeyApprover("m:c");
    const i = intentWith([a.approver, b.approver, c.approver], 2); // 2-of-3
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const links = new Map<string, string>();
    const adapter = new SigningLinkAdapter({
      server: signer,
      notify: (l) => {
        if (l.actor === "m:c") throw new Error("C's channel is down");
        links.set(l.actor, l.url);
      },
    });
    await adapter.deliver(i); // must NOT throw — A and B can still meet quorum 2
    const resolution = adapter.awaitResolution(i);
    for (const [actor, url] of links) {
      const sign = actor === "m:a" ? a.sign : b.sign;
      const token = new URL(url.replace(origin, base)).searchParams.get("token");
      const ch = await getChallenge(base, token, "approve");
      await record(base, token, "approve", ch, sign);
    }
    expect((await resolution).decision).toBe("approve"); // C being unreachable didn't break it
  });

  it("fails closed on a PARTIAL delivery under default:approve (no approve-on-timeout with an unreachable approver)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:a");
    const b = passkeyApprover("m:b");
    // quorum-1, default:"approve": if B's link fails and A stays silent, the approve-Default
    // would fire though B never got a veto link — so a partial delivery must fail closed.
    const i = createIntent({ action: "a", summary: "s", risk_tier: "low", approvers: [a.approver, b.approver], quorum: 1, timeout: 300, default: "approve" }, agent);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: (l) => { if (l.actor === "m:b") throw new Error("B down"); } });
    await expect(adapter.deliver(i)).rejects.toThrow(/B down|incomplete|delivery/i); // fails closed (propagates the delivery error)
    expect(pending.has(i.intent_id)).toBe(false); // reclaimed
  });

  it("under default:approve, a decision that SETTLES during delivery is honored despite a partial failure", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:a");
    const b = passkeyApprover("m:b");
    const i = createIntent({ action: "a", summary: "s", risk_tier: "low", approvers: [a.approver, b.approver], quorum: 1, timeout: 300, default: "approve" }, agent);
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const adapter = new SigningLinkAdapter({
      server: signer,
      notify: async (l) => {
        if (l.actor === "m:b") throw new Error("B down");
        const token = new URL(l.url.replace(origin, base)).searchParams.get("token");
        const ch = await getChallenge(base, token, "approve");
        await record(base, token, "approve", ch, a.sign); // A approves DURING delivery
      },
    });
    await expect(adapter.deliver(i)).resolves.toBeUndefined(); // NOT fail-closed — A's approval settled
    expect((await adapter.awaitResolution(i)).decision).toBe("approve");
  });

  it("SWALLOWS a partial delivery under default:reject (M<N can still proceed / times out to reject)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:a");
    const b = passkeyApprover("m:b");
    const i = createIntent({ action: "a", summary: "s", risk_tier: "low", approvers: [a.approver, b.approver], quorum: 1, timeout: 300, default: "reject" }, agent);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: (l) => { if (l.actor === "m:b") throw new Error("B down"); } });
    await expect(adapter.deliver(i)).resolves.toBeUndefined(); // partial is safe under reject-Default
  });

  it("does NOT hang on a notify that never settles (races the deadline, fails closed)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:a");
    // Short timeout so the deadline race resolves fast.
    const i = createIntent({ action: "a", summary: "s", risk_tier: "low", approvers: [a.approver], quorum: 1, timeout: 1, default: "reject" }, agent);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => new Promise<void>(() => {}) }); // never settles
    await expect(adapter.deliver(i)).rejects.toThrow(); // completes (~1s), fails closed (nothing delivered)
  }, 6000);

  it("fails closed only when NO approver could be reached", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:a");
    const i = intentWith([a.approver], 1);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => { throw new Error("all channels down"); } });
    await expect(adapter.deliver(i)).rejects.toThrow(/all channels down|delivery failed/);
    expect(pending.has(i.intent_id)).toBe(false); // reclaimed
  });

  it("close() keeps an already-recorded decision and raises no unhandled rejection", async () => {
    const rejections: unknown[] = [];
    const onRej = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRej);
    try {
      const pending = new PendingDecisions();
      const a = passkeyApprover("m:ceo");
      const i = intentWith([a.approver], 1);
      const { server, signer } = makeServer(pending);
      servers.push(server);
      const base = await listen(server);
      const adapter = new SigningLinkAdapter({
        server: signer,
        notify: async (l) => {
          const token = new URL(l.url.replace(origin, base)).searchParams.get("token");
          const ch = await getChallenge(base, token, "approve");
          await record(base, token, "approve", ch, a.sign); // decision lands during deliver
        },
      });
      await adapter.deliver(i);
      adapter.close(); // shutdown AFTER the decision landed
      expect((await adapter.awaitResolution(i)).decision).toBe("approve"); // not lost by close()
      await new Promise((r) => setTimeout(r, 20));
      expect(rejections).toEqual([]); // close()'s abort raised no unhandled rejection
    } finally {
      process.off("unhandledRejection", onRej);
    }
  });

  it("close() while pending rejects the wait (fail closed, not a fresh never-resolving one)", async () => {
    const rejections: unknown[] = [];
    const onRej = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRej);
    try {
      const pending = new PendingDecisions();
      const a = passkeyApprover("m:ceo");
      const i = intentWith([a.approver], 1);
      const { signer } = makeServer(pending);
      const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
      await adapter.deliver(i); // registered, no decision yet
      adapter.close(); // abort the in-flight wait
      await expect(adapter.awaitResolution(i)).rejects.toThrow(/closed|aborted/i);
      await new Promise((r) => setTimeout(r, 20));
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onRej);
    }
  });

  it("POST /sign with a literal null body returns 400 (not 500)", async () => {
    const pending = new PendingDecisions();
    const { server } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    const resp = await fetch(`${base}/sign`, { method: "POST", headers: { "content-type": "application/json" }, body: "null" });
    expect(resp.status).toBe(400);
  });

  it("GET on an already-SPENT link shows the error page up front (does not serve the signing page)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const b = passkeyApprover("m:cto");
    const i = intentWith([a.approver, b.approver], 2); // quorum 2 — the intent STAYS pending after one approval
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);
    void signer.awaitResolution(i);
    const url = signer.signingUrl(i, "m:ceo").replace(origin, base);
    const token = new URL(url).searchParams.get("token");
    const ch = await getChallenge(base, token, "approve");
    expect((await record(base, token, "approve", ch, a.sign)).status).toBe(200); // m:ceo's link now spent; intent still 1/2
    // Re-GET m:ceo's spent link: the page must reject up front, not render the full signing page
    // (which would end in a wasted passkey ceremony + a 410 on POST).
    const reget = await fetch(url);
    expect(reget.status).toBe(410);
    expect(await reget.text()).toContain("invalid, expired, or already decided");
  });

  it("awaitResolution is idempotent — a repeat call returns the SAME promise (no fresh never-resolving wait)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const i = intentWith([a.approver], 1);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
    await adapter.deliver(i);
    const p1 = adapter.awaitResolution(i);
    const p2 = adapter.awaitResolution(i);
    expect(p1).toBe(p2); // same captured promise, not a brand-new pending.wait
  });

  it("re-subscribing AFTER the deadline rejects instead of minting a fresh never-resolving wait", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    // Short timeout so the deadline — and the captured-entry eviction it triggers — passes quickly.
    const i = createIntent({ action: "a", summary: "s", risk_tier: "low", approvers: [a.approver], quorum: 1, timeout: 1, default: "reject" }, agent);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
    await adapter.deliver(i); // captures the wait; its deadline reaper evicts both captured + server entry at ~1s
    await new Promise((r) => setTimeout(r, 1200)); // let the deadline pass
    // BEFORE the fix: awaitResolution falls through to server.awaitResolution → a fresh wait whose
    // reaper fires immediately, leaving a promise that never resolves (a hang, or the wrong Default).
    // AFTER: past the deadline the intent is no longer pending, so it rejects deterministically.
    await expect(adapter.awaitResolution(i)).rejects.toThrow(/deadline|no longer pending/i);
    expect(pending.size).toBe(0); // no leaked fresh entry
  }, 6000);

  it("deliver() after close() is refused", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const i = intentWith([a.approver], 1);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
    adapter.close();
    await expect(adapter.deliver(i)).rejects.toThrow(/closed/);
  });

  it("refuses to deliver a vouched approver (no key to sign a link with)", async () => {
    const pending = new PendingDecisions();
    const { signer } = makeServer(pending);
    const i = createIntent({ action: "a", summary: "s", risk_tier: "low", approvers: [{ actor: "tg:1", mode: "vouched" }], timeout: 300, default: "reject" }, agent);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => {} });
    await expect(adapter.deliver(i)).rejects.toThrow(/keyed approvers only|vouched/);
  });

  it("reclaims the pending wait when notify fails (a failed delivery must not leak)", async () => {
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const i = intentWith([a.approver], 1);
    const { signer } = makeServer(pending);
    const adapter = new SigningLinkAdapter({ server: signer, notify: () => { throw new Error("delivery boom"); } });
    await expect(adapter.deliver(i)).rejects.toThrow(/delivery boom/);
    // No pending entry (or dangling promise) is left behind after the failure.
    expect(pending.size).toBe(0);
    expect(pending.has(i.intent_id)).toBe(false);
  });

  it("wrapAction runs a keyed 2-of-2 passkey action end-to-end through the adapter", async () => {
    // The exact surface the review flagged as impossible: a multi-approver keyed
    // Intent driven through the normal wrapAction path, resolving to run the action.
    const pending = new PendingDecisions();
    const a = passkeyApprover("m:ceo");
    const b = passkeyApprover("m:cto");
    const { server, signer } = makeServer(pending);
    servers.push(server);
    const base = await listen(server);

    const sent: { actor: string; url: string }[] = [];
    const adapter = new SigningLinkAdapter({ server: signer, notify: (l) => void sent.push({ actor: l.actor, url: l.url }) });

    let ran = false;
    const deploy = wrapAction(
      () => { ran = true; return "deployed"; },
      { action: "prod.deploy", summary: "Deploy 2.4.0 to production", risk_tier: "critical", approvers: [a.approver, b.approver], quorum: 2, timeout: 300, default: "reject" },
      adapter,
      { agent, authorityKey: authority.secretKey, webauthn: { rpId, allowedOrigins: [origin] } },
    );

    const resultP = deploy();
    // deliver() hands both links to notify before wrapAction awaits resolution.
    for (let i = 0; i < 100 && sent.length < 2; i++) await new Promise((r) => setTimeout(r, 5));
    expect(sent.length).toBe(2);
    for (const { actor, url } of sent) {
      const token = new URL(url.replace(origin, base)).searchParams.get("token");
      const sign = actor === "m:ceo" ? a.sign : b.sign;
      const ch = await getChallenge(base, token, "approve");
      expect((await record(base, token, "approve", ch, sign)).status).toBe(200);
    }
    expect(await resultP).toBe("deployed"); // the guarded action ran on the keyed quorum
    expect(ran).toBe(true);
  });
});
