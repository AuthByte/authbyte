import { Hono } from "hono";
import { canonicalEnvelope } from "./canonical.js";
import { fingerprint, scalarLength, verifyCanonical } from "./crypto.js";
import { ACTOR_RE, HANDLE_RE, isHttpsBlob, THREAD_RE } from "./ids.js";
import {
  BODY_AGE_BYTES,
  BODY_PLAIN_CAP,
  HMAC_SECRET_MIN,
  PROTOCOL,
  RETENTION_TTL_MAX,
  RETENTION_TTL_MIN,
  WIRE_VERSION,
  isAgeArmored,
  isIntent,
  isPriority,
  type Envelope,
} from "./types.js";
import { codeOf, MemoryStore, type Actor } from "./store.js";
import { dispatchInboxNew, type FetchLike } from "./webhooks.js";

export type AppOptions = {
  store: MemoryStore;
  publicBase?: string;
  fetchImpl?: FetchLike;
  webhookRetries?: number;
};

type ErrStatus = 400 | 401 | 403 | 404 | 409 | 410 | 413;

function fail(
  c: { json: (x: unknown, s?: ErrStatus) => Response },
  status: ErrStatus,
  error: string,
  hint: string,
) {
  return c.json({ error, hint }, status);
}

function bearer(c: { req: { header: (n: string) => string | undefined } }): string | null {
  const h = c.req.header("authorization") ?? "";
  const m = /^Bearer\s+(\S+)/i.exec(h);
  return m ? m[1] : null;
}

export function createApp(opts: AppOptions): Hono {
  const app = new Hono();
  const store = opts.store;
  const publicBase = (opts.publicBase ?? "http://127.0.0.1:8787").replace(/\/$/, "");

  function auth(
    c: { req: { header: (n: string) => string | undefined }; json: (x: unknown, s?: ErrStatus) => Response },
  ): Actor | Response {
    const token = bearer(c);
    if (!token) return fail(c, 401, "unauthorized", "Missing bearer token.");
    const actor = store.byToken(token);
    if (!actor) return fail(c, 401, "unauthorized", "Bad token.");
    return actor;
  }

  app.get("/v0/health", (c) =>
    c.json({ ok: true, protocol: PROTOCOL, v: WIRE_VERSION }),
  );

  app.post("/v0/handles/claim", async (c) => {
    let body: { handle?: string; recovery_secret?: string };
    try {
      body = await c.req.json();
    } catch {
      return fail(c, 400, "invalid_json", "JSON body required.");
    }
    const handle = (body.handle ?? "").trim().toLowerCase();
    try {
      const { actor, token, recovery_secret } = store.claim(
        handle,
        body.recovery_secret,
      );
      return c.json(
        {
          actor_id: actor.actorId,
          handle: actor.handle,
          token,
          recovery_secret,
          warning:
            "Store token and recovery_secret now. Both are shown once.",
        },
        201,
      );
    } catch (err) {
      const code = codeOf(err);
      if (code === "invalid_handle") {
        return fail(
          c,
          400,
          "invalid_handle",
          "3–32 chars, lowercase a-z 0-9, single hyphens inside.",
        );
      }
      if (code === "handle_taken") {
        return fail(c, 409, "handle_taken", "That handle is already claimed.");
      }
      throw err;
    }
  });

  app.post("/v0/handles/recover", async (c) => {
    let body: { handle?: string; recovery_secret?: string };
    try {
      body = await c.req.json();
    } catch {
      return fail(c, 400, "invalid_json", "JSON body required.");
    }
    const handle = (body.handle ?? "").trim().toLowerCase();
    const secret = body.recovery_secret ?? "";
    const result = store.recover(handle, secret);
    if (!result) {
      return fail(c, 401, "recover_failed", "Handle or recovery secret did not match.");
    }
    return c.json({
      actor_id: result.actor.actorId,
      handle: result.actor.handle,
      token: result.token,
    });
  });

  app.get("/v0/handles/me", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    return c.json(meJson(actor, store));
  });

  app.patch("/v0/handles/me", async (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    let body: { retention?: { enabled?: boolean; ttl_seconds?: number | null } };
    try {
      body = await c.req.json();
    } catch {
      return fail(c, 400, "invalid_json", "JSON body required.");
    }
    if (body.retention) {
      const enabled = Boolean(body.retention.enabled);
      let ttl = body.retention.ttl_seconds ?? null;
      if (enabled) {
        if (ttl === null || typeof ttl !== "number") {
          return fail(
            c,
            400,
            "retention_ttl_required",
            "Opt-in retention needs enabled=true and ttl_seconds.",
          );
        }
        if (ttl < RETENTION_TTL_MIN || ttl > RETENTION_TTL_MAX) {
          return fail(
            c,
            400,
            "retention_ttl_range",
            "ttl_seconds must be 3600–7776000.",
          );
        }
      } else {
        ttl = null;
      }
      actor.retention = { enabled, ttl_seconds: ttl };
    }
    return c.json(meJson(actor, store));
  });

  app.get("/v0/handles/:handle", (c) => {
    const handle = c.req.param("handle").toLowerCase();
    if (!HANDLE_RE.test(handle)) {
      return fail(c, 400, "invalid_handle", "Malformed handle.");
    }
    const actor = store.byHandle(handle);
    if (!actor) return fail(c, 404, "not_found", "No actor with that handle.");
    return c.json({
      handle: actor.handle,
      actor_id: actor.actorId,
      age_public_key: actor.agePublicKey ?? null,
      signing_public_key: actor.signingPublicKey ?? null,
      created_at: new Date(actor.createdAt).toISOString(),
    });
  });

  app.post("/v0/keys/age", async (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const body = await readJson<{ public_key?: string }>(c);
    if (body instanceof Response) return body;
    try {
      store.publishAge(actor, body.public_key ?? "");
    } catch {
      return fail(c, 400, "invalid_age_key", "Expected an age1… recipient string.");
    }
    return c.json({
      fingerprint: fingerprint(actor.agePublicKey!),
      published_at: new Date(store.now()).toISOString(),
    });
  });

  app.post("/v0/keys/signing", async (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const body = await readJson<{ public_key?: string }>(c);
    if (body instanceof Response) return body;
    try {
      store.publishSigning(actor, body.public_key ?? "");
    } catch {
      return fail(
        c,
        400,
        "invalid_signing_key",
        "Expected ed25519:<base64url raw public key>.",
      );
    }
    return c.json({
      fingerprint: fingerprint(actor.signingPublicKey!),
      published_at: new Date(store.now()).toISOString(),
    });
  });

  app.post("/v0/invites", async (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    let note: string | undefined;
    try {
      const body = await c.req.json();
      if (typeof body?.note === "string") note = body.note.slice(0, 500);
    } catch {
      /* empty body is fine */
    }
    const inv = store.createInvite(actor.actorId, note);
    return c.json(
      {
        invite_id: inv.token,
        token: inv.token,
        url: `${publicBase}/i/${inv.token}`,
        expires_at: new Date(inv.expiresAt).toISOString(),
      },
      201,
    );
  });

  app.get("/i/:token", (c) => {
    const inv = store.getInvite(c.req.param("token"));
    if (!inv || inv.redeemed || inv.expiresAt <= store.now()) {
      return c.text("Invite unknown, spent, or expired.\n", 404);
    }
    const issuer = store.byId(inv.fromActorId);
    return c.text(
      [
        "Latch invite",
        "",
        `From handle: ${issuer?.handle ?? "unknown"}`,
        `From actor:  ${inv.fromActorId}`,
        inv.note ? `Note: ${inv.note}` : "",
        "",
        "This note is for humans. Redeeming does not send mail.",
        "",
        `latch redeem ${inv.token}`,
        `POST ${publicBase}/v0/invites/${inv.token}/redeem`,
        "",
      ]
        .filter((l) => l !== undefined)
        .join("\n"),
    );
  });

  app.post("/v0/invites/:token/redeem", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    try {
      const grant = store.redeem(c.req.param("token"), actor);
      const view = store.grantView(grant, actor.actorId);
      return c.json({
        grant_id: grant.id,
        peer: {
          actor_id: view.peer.actor_id,
          handle: view.peer.handle,
          age_public_key: store.byId(view.peer.actor_id)?.agePublicKey ?? null,
          signing_public_key:
            store.byId(view.peer.actor_id)?.signingPublicKey ?? null,
        },
      });
    } catch (err) {
      const code = codeOf(err);
      if (code === "unknown_invite") {
        return fail(c, 404, "unknown_invite", "No such invite.");
      }
      if (code === "invite_spent") {
        return fail(c, 410, "invite_spent", "That invite was already redeemed.");
      }
      if (code === "invite_expired") {
        return fail(c, 410, "invite_expired", "That invite expired.");
      }
      if (code === "self_redeem") {
        return fail(c, 400, "self_redeem", "You cannot redeem your own invite.");
      }
      if (code === "already_granted") {
        return fail(c, 409, "already_granted", "A grant with this peer already exists.");
      }
      throw err;
    }
  });

  app.get("/v0/grants", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    return c.json({ grants: store.listGrants(actor.actorId) });
  });

  app.post("/v0/grants/:id/repin", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const grant = store.grantById(c.req.param("id"), actor.actorId);
    if (!grant) return fail(c, 404, "not_found", "No such grant.");
    store.repin(grant, actor.actorId);
    return c.json(store.grantView(grant, actor.actorId));
  });

  app.delete("/v0/grants/:id", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const grant = store.grantById(c.req.param("id"), actor.actorId);
    if (!grant) return fail(c, 404, "not_found", "No such grant.");
    store.revoke(grant);
    return c.json({ revoked: true, grant_id: grant.id });
  });

  app.post("/v0/messages", async (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const body = await readJson<Partial<Envelope>>(c);
    if (body instanceof Response) return body;
    const env = validateEnvelope(body);
    if ("error" in env) {
      return fail(c, env.status, env.error, env.hint);
    }
    if (env.from !== actor.actorId) {
      return fail(c, 403, "from_mismatch", "Envelope from must match the bearer actor.");
    }
    if (!actor.signingPublicKey) {
      return fail(
        c,
        400,
        "signing_key_required",
        "Publish an Ed25519 key before sending.",
      );
    }
    const canonical = canonicalEnvelope({
      v: env.v,
      id: env.id,
      from: env.from,
      to: env.to,
      intent: env.intent,
      priority: env.priority,
      thread_id: env.thread_id,
      body: env.body,
      blob_url: env.blob_url,
    });
    if (!verifyCanonical(actor.signingPublicKey, canonical, env.sig)) {
      return fail(c, 400, "bad_signature", "Envelope sig did not verify.");
    }
    const grant = store.findGrant(env.from, env.to);
    if (!grant) {
      return fail(c, 403, "no_grant", "No mutual grant. Exchange an invite first.");
    }
    const view = store.grantView(grant, actor.actorId);
    if (view.status === "key_changed") {
      return fail(
        c,
        409,
        "key_changed",
        "Peer key no longer matches the pin. Halt and re-verify out of band, then repin.",
      );
    }
    const recipient = store.byId(env.to);
    if (!recipient) {
      return fail(c, 404, "not_found", "Recipient actor does not exist.");
    }
    const pinnedAge = view.pinned_age_key;
    if (pinnedAge) {
      if (!isAgeArmored(env.body)) {
        return fail(
          c,
          400,
          "encryption_required",
          "Recipient published an age key. Body must be ASCII-armored age ciphertext.",
        );
      }
      if (Buffer.byteLength(env.body, "utf8") > BODY_AGE_BYTES) {
        return fail(c, 413, "body_too_large", "Age-armored body exceeds 8192 bytes.");
      }
    } else {
      if (isAgeArmored(env.body)) {
        return fail(
          c,
          400,
          "plaintext_required",
          "Recipient has no age key; send plaintext (≤500 chars).",
        );
      }
      if (scalarLength(env.body) > BODY_PLAIN_CAP) {
        return fail(c, 413, "body_too_large", "Plaintext body exceeds 500 characters.");
      }
    }
    try {
      const { message, replayed } = store.enqueue(env);
      if (!replayed) {
        const dest = recipient.webhook;
        if (dest) {
          try {
            await dispatchInboxNew({
              url: dest.url,
              secret: dest.secret,
              to: recipient.actorId,
              unread: store.unreadCount(recipient.actorId),
              now: store.now,
              fetchImpl: opts.fetchImpl,
              retries: opts.webhookRetries ?? 3,
            });
          } catch {
            /* queued mail is the source of truth */
          }
        }
      }
      return c.json(
        {
          id: message.envelope.id,
          queued_at: new Date(message.queuedAt).toISOString(),
          expires_at: new Date(message.expiresAt).toISOString(),
          replayed,
        },
        replayed ? 200 : 201,
      );
    } catch (err) {
      if (codeOf(err) === "idempotency_conflict") {
        return fail(
          c,
          409,
          "idempotency_conflict",
          "This id was already used with a different envelope.",
        );
      }
      throw err;
    }
  });

  app.get("/v0/inbox/headers", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const messages = store.headers(actor.actorId);
    return c.json({
      unread: messages.length,
      webhook_connected: Boolean(actor.webhook),
      messages,
    });
  });

  app.get("/v0/inbox/:id", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const id = c.req.param("id");
    const result = store.open(actor.actorId, id);
    if (result === "missing") {
      return fail(c, 404, "not_found", "No such inbox item for this actor.");
    }
    if (result === "gone") {
      const m = store.messages.get(id)!;
      return c.json({ ...store.receipt(m), error: "content_deleted" }, 410);
    }
    return c.json({
      ...result.envelope,
      body: result.payload,
    });
  });

  app.post("/v0/inbox/:id/ack", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const result = store.ack(actor.actorId, c.req.param("id"));
    if (result === "missing") {
      return fail(c, 404, "not_found", "No such inbox item for this actor.");
    }
    return c.json(result);
  });

  app.put("/v0/notifications", async (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    const body = await readJson<{ url?: string; secret?: string }>(c);
    if (body instanceof Response) return body;
    const url = body.url ?? "";
    const secret = body.secret ?? "";
    try {
      const u = new URL(url);
      if (u.protocol !== "https:" && u.protocol !== "http:") {
        return fail(c, 400, "invalid_url", "Webhook URL must be http(s).");
      }
    } catch {
      return fail(c, 400, "invalid_url", "Webhook URL must be http(s).");
    }
    if (secret.length < HMAC_SECRET_MIN) {
      return fail(c, 400, "weak_secret", "HMAC secret must be at least 32 characters.");
    }
    store.setWebhook(actor, url, secret);
    return c.json({ connected: true, url });
  });

  app.get("/v0/notifications", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    if (!actor.webhook) return c.json({ connected: false });
    return c.json({ connected: true, url: actor.webhook.url });
  });

  app.delete("/v0/notifications", (c) => {
    const actor = auth(c);
    if (actor instanceof Response) return actor;
    store.clearWebhook(actor);
    return c.json({ connected: false });
  });

  return app;
}

function meJson(actor: Actor, store: MemoryStore) {
  return {
    actor_id: actor.actorId,
    handle: actor.handle,
    age_public_key: actor.agePublicKey ?? null,
    signing_public_key: actor.signingPublicKey ?? null,
    retention: actor.retention,
    webhook_connected: Boolean(actor.webhook),
  };
}

async function readJson<T>(
  c: {
    req: { json: () => Promise<unknown> };
    json: (x: unknown, s?: ErrStatus) => Response;
  },
): Promise<T | Response> {
  try {
    return (await c.req.json()) as T;
  } catch {
    return fail(c, 400, "invalid_json", "JSON body required.");
  }
}

function validateEnvelope(body: Partial<Envelope>): Envelope | {
  status: ErrStatus;
  error: string;
  hint: string;
} {
  if (body.v !== 0) {
    return { status: 400, error: "bad_version", hint: "v must be 0." };
  }
  if (typeof body.id !== "string" || !/^msg_[A-Za-z0-9_-]{8,64}$/.test(body.id)) {
    return {
      status: 400,
      error: "bad_id",
      hint: "id must be a sender-generated msg_… string.",
    };
  }
  if (typeof body.from !== "string" || !ACTOR_RE.test(body.from)) {
    return { status: 400, error: "bad_from", hint: "from must be an actor id." };
  }
  if (typeof body.to !== "string" || !ACTOR_RE.test(body.to)) {
    return { status: 400, error: "bad_to", hint: "to must be an actor id." };
  }
  if (body.from === body.to) {
    return { status: 400, error: "self_send", hint: "Cannot send to yourself." };
  }
  if (!isIntent(body.intent)) {
    return {
      status: 400,
      error: "unknown_intent",
      hint: "intent allowlist is message and status only.",
    };
  }
  if (!isPriority(body.priority)) {
    return { status: 400, error: "bad_priority", hint: "priority is low|normal|high." };
  }
  if (body.thread_id !== undefined && !THREAD_RE.test(body.thread_id)) {
    return {
      status: 400,
      error: "bad_thread",
      hint: "thread_id must match thr_[A-Za-z0-9_-]{1,64}.",
    };
  }
  if (typeof body.body !== "string") {
    return { status: 400, error: "bad_body", hint: "body is required." };
  }
  if (body.blob_url !== undefined && !isHttpsBlob(body.blob_url)) {
    return {
      status: 400,
      error: "bad_blob_url",
      hint: "blob_url must be https with no credentials in the URL.",
    };
  }
  if (typeof body.sig !== "string" || body.sig.length < 16) {
    return { status: 400, error: "bad_signature", hint: "sig is required." };
  }
  return body as Envelope;
}
