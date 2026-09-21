import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { canonicalEnvelope } from "../src/canonical.js";
import {
  generateSigning,
  hmacValid,
  signCanonical,
} from "../src/crypto.js";
import { messageId } from "../src/ids.js";
import { MemoryStore } from "../src/store.js";
import type { Envelope, Intent, Priority } from "../src/types.js";

type Json = Record<string, unknown>;

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

async function register(app: ReturnType<typeof createApp>, handle: string) {
  const claimed = await json(app, "POST", "/v0/handles/claim", { body: { handle } });
  expect(claimed.status).toBe(201);
  const signing = generateSigning();
  const pub = await json(app, "POST", "/v0/keys/signing", {
    token: String(claimed.body.token),
    body: { public_key: signing.publicWire },
  });
  expect(pub.status).toBe(200);
  return {
    handle,
    actor_id: String(claimed.body.actor_id),
    token: String(claimed.body.token),
    recovery_secret: String(claimed.body.recovery_secret),
    signing,
  };
}

function signedEnvelope(
  actor: Awaited<ReturnType<typeof register>>,
  to: string,
  body: string,
  extra?: { intent?: Intent; priority?: Priority; thread_id?: string; id?: string },
): Envelope {
  const unsigned = {
    v: 0 as const,
    id: extra?.id ?? messageId(),
    from: actor.actor_id,
    to,
    intent: extra?.intent ?? ("message" as const),
    priority: extra?.priority ?? ("normal" as const),
    thread_id: extra?.thread_id,
    body,
  };
  return {
    ...unsigned,
    sig: signCanonical(actor.signing.privatePem, canonicalEnvelope(unsigned)),
  };
}

describe("Latch v0 hot path", () => {
  it("send → headers → open → ack deletes payload", async () => {
    const store = new MemoryStore();
    const app = createApp({ store, webhookRetries: 1 });
    const alice = await register(app, "alice-bot");
    const bob = await register(app, "bob-bot");

    const invite = await json(app, "POST", "/v0/invites", {
      token: alice.token,
      body: { note: "humans agreed to swap notes" },
    });
    expect(invite.status).toBe(201);
    const token = String(invite.body.token);

    const redeem = await json(
      app,
      "POST",
      `/v0/invites/${token}/redeem`,
      { token: bob.token },
    );
    expect(redeem.status).toBe(200);
    expect(redeem.body.grant_id).toBeTruthy();

    const afterGrant = await json(app, "GET", "/v0/inbox/headers", {
      token: bob.token,
    });
    expect(afterGrant.status).toBe(200);
    expect(afterGrant.body.unread).toBe(0);

    const sent = await json(app, "POST", "/v0/messages", {
      token: alice.token,
      body: signedEnvelope(alice, bob.actor_id, "venue changed, 6pm", {
        thread_id: "thr_dinner",
      }),
    });
    expect(sent.status).toBe(201);
    const id = String(sent.body.id);

    const headers = await json(app, "GET", "/v0/inbox/headers", {
      token: bob.token,
    });
    expect(headers.status).toBe(200);
    expect(headers.body.unread).toBe(1);
    const messages = headers.body.messages as Json[];
    expect(messages).toHaveLength(1);
    expect(messages[0]).not.toHaveProperty("body");
    expect(messages[0].id).toBe(id);
    expect(messages[0].from).toBe(alice.actor_id);
    expect(messages[0].intent).toBe("message");
    expect(JSON.stringify(headers.body)).not.toContain("venue changed");

    const opened = await json(app, "GET", `/v0/inbox/${id}`, { token: bob.token });
    expect(opened.status).toBe(200);
    expect(opened.body.body).toBe("venue changed, 6pm");
    expect(opened.body.sig).toBeTruthy();

    const acked = await json(app, "POST", `/v0/inbox/${id}/ack`, {
      token: bob.token,
    });
    expect(acked.status).toBe(200);
    expect(acked.body.status).toBe("acked");
    expect(acked.body).not.toHaveProperty("body");
    expect(acked.body.id).toBe(id);
    expect(acked.body.bytes).toBeGreaterThan(0);

    const gone = await json(app, "GET", `/v0/inbox/${id}`, { token: bob.token });
    expect(gone.status).toBe(410);
    expect(gone.body.status).toBe("acked");
    expect(gone.body.body).toBeUndefined();
    expect(JSON.stringify(gone.body)).not.toContain("venue changed");

    const empty = await json(app, "GET", "/v0/inbox/headers", { token: bob.token });
    expect(empty.body.unread).toBe(0);
    expect(empty.body.messages).toEqual([]);
  });

  it("grant invite is mutual and does not auto-send mail", async () => {
    const app = createApp({ store: new MemoryStore(), webhookRetries: 1 });
    const nebula = await register(app, "nebula");
    const friend = await register(app, "friend-bot");

    const invite = await json(app, "POST", "/v0/invites", { token: nebula.token });
    const redeem = await json(
      app,
      "POST",
      `/v0/invites/${String(invite.body.token)}/redeem`,
      { token: friend.token },
    );
    expect(redeem.status).toBe(200);
    expect((redeem.body.peer as Json).handle).toBe("nebula");

    const g1 = await json(app, "GET", "/v0/grants", { token: nebula.token });
    const g2 = await json(app, "GET", "/v0/grants", { token: friend.token });
    const grants1 = g1.body.grants as Json[];
    const grants2 = g2.body.grants as Json[];
    expect(grants1).toHaveLength(1);
    expect(grants2).toHaveLength(1);
    expect((grants1[0].peer as Json).handle).toBe("friend-bot");
    expect(grants1[0].status).toBe("active");
    expect(grants2[0].status).toBe("active");

    for (const token of [nebula.token, friend.token]) {
      const inbox = await json(app, "GET", "/v0/inbox/headers", { token });
      expect(inbox.body.unread).toBe(0);
    }

    const badIntent = await json(app, "POST", "/v0/messages", {
      token: nebula.token,
      body: signedEnvelope(nebula, friend.actor_id, "do this task", {
        intent: "need_help" as unknown as Intent,
      }),
    });
    expect(badIntent.status).toBe(400);
    expect(badIntent.body.error).toBe("unknown_intent");
  });

  it("signs inbox.new webhooks with HMAC over timestamp.body", async () => {
    const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const app = createApp({
      store: new MemoryStore(),
      webhookRetries: 1,
      fetchImpl: async (url, init) => {
        calls.push({
          url,
          headers: init.headers,
          body: init.body,
        });
        return { ok: true, status: 200 };
      },
    });
    const alice = await register(app, "sender");
    const bob = await register(app, "receiver");
    const invite = await json(app, "POST", "/v0/invites", { token: alice.token });
    await json(app, "POST", `/v0/invites/${String(invite.body.token)}/redeem`, {
      token: bob.token,
    });

    const secret = "s".repeat(32);
    const dest = "http://127.0.0.1:9999/wake";
    const put = await json(app, "PUT", "/v0/notifications", {
      token: bob.token,
      body: { url: dest, secret },
    });
    expect(put.status).toBe(200);
    expect(put.body.connected).toBe(true);
    const listed = await json(app, "GET", "/v0/notifications", { token: bob.token });
    expect(listed.body).not.toHaveProperty("secret");

    await json(app, "POST", "/v0/messages", {
      token: alice.token,
      body: signedEnvelope(alice, bob.actor_id, "ping"),
    });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(dest);
    expect(calls[0].headers["x-latch-event"]).toBe("inbox.new");
    const ts = calls[0].headers["x-latch-timestamp"];
    const sig = calls[0].headers["x-latch-signature"];
    expect(hmacValid(secret, ts, calls[0].body, sig)).toBe(true);
    expect(hmacValid("wrong".padEnd(32, "x"), ts, calls[0].body, sig)).toBe(false);

    const wake = JSON.parse(calls[0].body) as Json;
    expect(wake).toEqual({
      event: "inbox.new",
      to: bob.actor_id,
      unread: 1,
    });
    expect(JSON.stringify(wake)).not.toContain("ping");
    expect(JSON.stringify(wake)).not.toContain(alice.actor_id);
    expect(JSON.stringify(wake)).not.toContain("sender");
  });

  it("retention is off by default and ack forgets the body", async () => {
    const store = new MemoryStore();
    const app = createApp({ store, webhookRetries: 1 });
    const alice = await register(app, "keep-off-a");
    const bob = await register(app, "keep-off-b");
    const me = await json(app, "GET", "/v0/handles/me", { token: bob.token });
    expect(me.body.retention).toEqual({ enabled: false, ttl_seconds: null });

    const invite = await json(app, "POST", "/v0/invites", { token: alice.token });
    await json(app, "POST", `/v0/invites/${String(invite.body.token)}/redeem`, {
      token: bob.token,
    });
    const sent = await json(app, "POST", "/v0/messages", {
      token: alice.token,
      body: signedEnvelope(alice, bob.actor_id, "secret-payload-xyz"),
    });
    const id = String(sent.body.id);
    await json(app, "POST", `/v0/inbox/${id}/ack`, { token: bob.token });

    const stored = store.messages.get(id);
    expect(stored?.payload).toBeNull();
    expect(stored?.envelope.body).toBe("");
    expect(stored?.status).toBe("acked");

    const patch = await json(app, "PATCH", "/v0/handles/me", {
      token: bob.token,
      body: { retention: { enabled: true } },
    });
    expect(patch.status).toBe(400);
    expect(patch.body.error).toBe("retention_ttl_required");
  });
});
