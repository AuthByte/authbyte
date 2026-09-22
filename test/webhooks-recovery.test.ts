import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { canonicalEnvelope } from "../src/canonical.js";
import {
  ageEncrypt,
  generateAge,
  generateSigning,
  hmacValid,
  signCanonical,
} from "../src/crypto.js";
import { messageId } from "../src/ids.js";
import { MemoryStore } from "../src/store.js";
import { webhookDispatchHeaders } from "../src/webhooks.js";
import type { Envelope } from "../src/types.js";

type Json = Record<string, unknown>;

const OPS = "test-ops-secret-not-for-production-use";
const JOIN = "fleet-join-code-test-only";
const HMAC = "hmac-test-secret-not-production-32b";
const GROK_AUTH = "Bearer test-sender-key-not-a-real-host-credential";

async function json(
  app: ReturnType<typeof createApp>,
  method: string,
  path: string,
  opts?: { token?: string; body?: unknown },
): Promise<{ status: number; body: Json }> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (opts?.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts?.body !== undefined) headers["content-type"] = "application/json";
  const res = await app.request(path, {
    method,
    headers,
    body: opts?.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Json) : {} };
}

function leak(hay: unknown, ...needles: string[]): string[] {
  const s = JSON.stringify(hay);
  return needles.filter((n) => s.includes(n));
}

describe("Grok authorization wakes + recovery", () => {
  it("sends the exact Authorization header for Grok mode and keeps HMAC compatible", async () => {
    const grokCalls: Array<{ headers: Record<string, string>; body: string }> = [];
    const hmacCalls: Array<{ headers: Record<string, string>; body: string }> = [];

    const grokApp = createApp({
      store: new MemoryStore(),
      webhookRetries: 1,
      fetchImpl: async (_url, init) => {
        grokCalls.push({ headers: init.headers, body: init.body });
        return { ok: true, status: 200 };
      },
    });
    const hmacApp = createApp({
      store: new MemoryStore(),
      webhookRetries: 1,
      fetchImpl: async (_url, init) => {
        hmacCalls.push({ headers: init.headers, body: init.body });
        return { ok: true, status: 200 };
      },
    });

    async function pair(app: ReturnType<typeof createApp>) {
      const a = await json(app, "POST", "/v0/handles/claim", { body: { handle: "sender" } });
      const b = await json(app, "POST", "/v0/handles/claim", { body: { handle: "receiver" } });
      const sa = generateSigning();
      const sb = generateSigning();
      const aa = await generateAge();
      const ab = await generateAge();
      for (const [token, signing, age] of [
        [String(a.body.token), sa, aa],
        [String(b.body.token), sb, ab],
      ] as const) {
        await json(app, "POST", "/v0/keys/signing", {
          token,
          body: { public_key: signing.publicWire },
        });
        await json(app, "POST", "/v0/keys/age", {
          token,
          body: { public_key: age.recipient },
        });
      }
      const inv = await json(app, "POST", "/v0/invites", { token: String(a.body.token) });
      await json(app, "POST", `/v0/invites/${String(inv.body.token)}/redeem`, {
        token: String(b.body.token),
      });
      return {
        fromToken: String(a.body.token),
        toToken: String(b.body.token),
        fromId: String(a.body.actor_id),
        toId: String(b.body.actor_id),
        signing: sa,
        toAge: ab.recipient,
      };
    }

    const grok = await pair(grokApp);
    const putGrok = await json(grokApp, "PUT", "/v0/notifications", {
      token: grok.toToken,
      body: {
        url: "https://example.test/automations/webhook/test-routine",
        auth_mode: "authorization",
        authorization: GROK_AUTH,
      },
    });
    expect(putGrok.status).toBe(200);
    expect(putGrok.body.auth_mode).toBe("authorization");
    expect(leak(putGrok.body, GROK_AUTH, "test-sender-key")).toEqual([]);

    const listed = await json(grokApp, "GET", "/v0/notifications", {
      token: grok.toToken,
    });
    expect(listed.body.connected).toBe(true);
    expect(listed.body).not.toHaveProperty("secret");
    expect(listed.body).not.toHaveProperty("authorization");
    expect(leak(listed.body, GROK_AUTH)).toEqual([]);

    const wire = await ageEncrypt(grok.toAge, "hello");
    const unsigned = {
      v: 0 as const,
      id: messageId(),
      from: grok.fromId,
      to: grok.toId,
      intent: "message" as const,
      priority: "normal" as const,
      body: wire,
    };
    const env: Envelope = {
      ...unsigned,
      sig: signCanonical(grok.signing.privatePem, canonicalEnvelope(unsigned)),
    };
    expect(
      (await json(grokApp, "POST", "/v0/messages", { token: grok.fromToken, body: env }))
        .status,
    ).toBe(201);
    expect(grokCalls).toHaveLength(1);
    expect(grokCalls[0].headers.authorization).toBe(GROK_AUTH);
    expect(grokCalls[0].headers["x-latch-signature"]).toBeUndefined();
    const wake = JSON.parse(grokCalls[0].body) as Json;
    expect(wake.event).toBe("inbox.new");
    expect(wake.to).toBe(grok.toId);
    expect(JSON.stringify(wake)).not.toContain("hello");

    const hmac = await pair(hmacApp);
    const putHmac = await json(hmacApp, "PUT", "/v0/notifications", {
      token: hmac.toToken,
      body: { url: "http://127.0.0.1:9/hmac", secret: HMAC },
    });
    expect(putHmac.status).toBe(200);
    expect(putHmac.body.auth_mode).toBe("hmac");
    expect(leak(putHmac.body, HMAC)).toEqual([]);

    const wire2 = await ageEncrypt(hmac.toAge, "hello");
    const u2 = {
      v: 0 as const,
      id: messageId(),
      from: hmac.fromId,
      to: hmac.toId,
      intent: "message" as const,
      priority: "normal" as const,
      body: wire2,
    };
    await json(hmacApp, "POST", "/v0/messages", {
      token: hmac.fromToken,
      body: {
        ...u2,
        sig: signCanonical(hmac.signing.privatePem, canonicalEnvelope(u2)),
      },
    });
    expect(hmacCalls).toHaveLength(1);
    expect(hmacCalls[0].headers.authorization).toBeUndefined();
    expect(
      hmacValid(
        HMAC,
        hmacCalls[0].headers["x-latch-timestamp"],
        hmacCalls[0].body,
        hmacCalls[0].headers["x-latch-signature"],
      ),
    ).toBe(true);
  });

  it("join code cannot hijack a handle; reset token reclaims and clears webhook", async () => {
    const store = new MemoryStore();
    const app = createApp({
      store,
      webhookRetries: 1,
      opsSecret: OPS,
      joinCode: JOIN,
    });

    const joined = await json(app, "POST", `/j/${JOIN}`, {
      body: {
        handle: "nebula",
        webhook_url: "http://127.0.0.1:8765/latch/wake",
        webhook_secret: HMAC,
      },
    });
    expect(joined.status).toBe(201);
    const oldToken = String(joined.body.token);

    const hijack = await json(app, "POST", `/j/${JOIN}`, {
      body: {
        handle: "nebula",
        webhook_url: "https://example.test/stolen",
        webhook_secret: HMAC,
        join_code: JOIN,
      },
    });
    expect(hijack.status).toBe(409);
    expect(hijack.body.error).toBe("handle_taken");

    const still = await json(app, "GET", "/v0/handles/me", { token: oldToken });
    expect(still.status).toBe(200);
    expect((still.body.webhook as Json).url).toBe("http://127.0.0.1:8765/latch/wake");
    expect(leak(still.body, HMAC)).toEqual([]);

    const opsList = await json(app, "GET", "/v0/ops/agents", { token: OPS });
    expect(opsList.status).toBe(200);
    expect(leak(opsList.body, HMAC, String(joined.body.recovery_secret), oldToken)).toEqual(
      [],
    );

    const badOps = await json(app, "POST", "/v0/ops/agents/nebula/reset-credentials", {
      token: JOIN,
    });
    expect(badOps.status).toBe(401);

    const reset = await json(app, "POST", "/v0/ops/agents/nebula/reset-credentials", {
      token: OPS,
    });
    expect(reset.status).toBe(200);
    const resetToken = String(reset.body.reset_token);
    expect(resetToken.startsWith("lrt_")).toBe(true);

    const reclaim = await json(app, "POST", "/v0/handles/reclaim", {
      body: { handle: "nebula", reset_token: resetToken },
    });
    expect(reclaim.status).toBe(200);
    expect(reclaim.body.token).not.toBe(oldToken);
    expect((reclaim.body.webhook as Json).connected).toBe(false);

    const replay = await json(app, "POST", "/v0/handles/reclaim", {
      body: { handle: "nebula", reset_token: resetToken },
    });
    expect(replay.status).toBe(401);

    const dead = await json(app, "GET", "/v0/handles/me", { token: oldToken });
    expect(dead.status).toBe(401);

    const live = await json(app, "GET", "/v0/handles/me", {
      token: String(reclaim.body.token),
    });
    expect(live.status).toBe(200);
    expect(live.body.webhook_connected).toBe(false);
    expect(leak(live.body, HMAC, String(reclaim.body.recovery_secret))).toEqual([]);
  });

  it("redacts webhook secrets from operator and self views", async () => {
    const app = createApp({
      store: new MemoryStore(),
      opsSecret: OPS,
      webhookRetries: 1,
    });
    const claimed = await json(app, "POST", "/v0/handles/claim", {
      body: { handle: "redact-bot" },
    });
    const put = await json(app, "PUT", "/v0/notifications", {
      token: String(claimed.body.token),
      body: {
        url: "https://example.test/wake",
        auth_mode: "both",
        secret: HMAC,
        authorization: GROK_AUTH,
      },
    });
    expect(put.status).toBe(200);
    const me = await json(app, "GET", "/v0/handles/me", {
      token: String(claimed.body.token),
    });
    const note = await json(app, "GET", "/v0/notifications", {
      token: String(claimed.body.token),
    });
    const ops = await json(app, "GET", "/v0/ops/agents", { token: OPS });
    for (const view of [put.body, me.body, note.body, ops.body]) {
      expect(leak(view, HMAC, GROK_AUTH, "test-sender-key")).toEqual([]);
      expect(view).not.toHaveProperty("secret");
      expect(view).not.toHaveProperty("authorization");
      expect(view).not.toHaveProperty("webhook_secret");
    }
  });

  it("rejects send until age and signing keys are published", async () => {
    const app = createApp({ store: new MemoryStore(), webhookRetries: 1 });
    const a = await json(app, "POST", "/v0/handles/claim", { body: { handle: "no-keys" } });
    const b = await json(app, "POST", "/v0/handles/claim", { body: { handle: "peer" } });
    const sa = generateSigning();
    const sb = generateSigning();
    const aa = await generateAge();
    const ab = await generateAge();
    await json(app, "POST", "/v0/keys/signing", {
      token: String(b.body.token),
      body: { public_key: sb.publicWire },
    });
    await json(app, "POST", "/v0/keys/age", {
      token: String(b.body.token),
      body: { public_key: ab.recipient },
    });
    const inv = await json(app, "POST", "/v0/invites", { token: String(a.body.token) });
    await json(app, "POST", `/v0/invites/${String(inv.body.token)}/redeem`, {
      token: String(b.body.token),
    });

    const unsigned = {
      v: 0 as const,
      id: messageId(),
      from: String(a.body.actor_id),
      to: String(b.body.actor_id),
      intent: "message" as const,
      priority: "normal" as const,
      body: await ageEncrypt(ab.recipient, "too soon"),
    };
    const env = {
      ...unsigned,
      sig: signCanonical(sa.privatePem, canonicalEnvelope(unsigned)),
    };
    const blocked = await json(app, "POST", "/v0/messages", {
      token: String(a.body.token),
      body: env,
    });
    expect(blocked.status).toBe(400);
    expect(blocked.body.error).toBe("keys_required");

    await json(app, "POST", "/v0/keys/signing", {
      token: String(a.body.token),
      body: { public_key: sa.publicWire },
    });
    const still = await json(app, "POST", "/v0/messages", {
      token: String(a.body.token),
      body: env,
    });
    expect(still.status).toBe(400);
    expect(still.body.error).toBe("keys_required");

    await json(app, "POST", "/v0/keys/age", {
      token: String(a.body.token),
      body: { public_key: aa.recipient },
    });
    const ok = await json(app, "POST", "/v0/messages", {
      token: String(a.body.token),
      body: env,
    });
    expect(ok.status).toBe(201);
  });

  it("builds Grok Authorization headers without HMAC unless both", () => {
    const grok = webhookDispatchHeaders({
      authMode: "authorization",
      timestamp: "1",
      rawBody: "{}",
      authorization: GROK_AUTH,
    });
    expect(grok.authorization).toBe(GROK_AUTH);
    expect(grok["x-latch-signature"]).toBeUndefined();

    const hmac = webhookDispatchHeaders({
      authMode: "hmac",
      timestamp: "1",
      rawBody: "{}",
      hmacSecret: HMAC,
    });
    expect(hmac.authorization).toBeUndefined();
    expect(hmac["x-latch-signature"]?.startsWith("sha256=")).toBe(true);
  });
});
