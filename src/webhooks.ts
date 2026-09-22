import { hmacSignature } from "./crypto.js";
import type { AuthMode } from "./types.js";

export type WakeBody = {
  event: "inbox.new";
  to: string;
  unread: number;
};

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number }>;

export type WebhookDest = {
  url: string;
  authMode: AuthMode;
  secret?: string;
  authorization?: string;
};

const BACKOFF_MS = [1000, 4000, 16000];

export function webhookDispatchHeaders(opts: {
  authMode: AuthMode;
  timestamp: string;
  rawBody: string;
  hmacSecret?: string;
  authorization?: string;
}): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-latch-event": "inbox.new",
    "x-latch-timestamp": opts.timestamp,
  };
  if (opts.authMode === "hmac" || opts.authMode === "both") {
    if (!opts.hmacSecret) throw new Error("hmac_secret_required");
    headers["x-latch-signature"] = hmacSignature(
      opts.hmacSecret,
      opts.timestamp,
      opts.rawBody,
    );
  }
  if (opts.authMode === "authorization" || opts.authMode === "both") {
    if (!opts.authorization) throw new Error("authorization_required");
    headers.authorization = opts.authorization;
  }
  return headers;
}

/** Safe to return to operators and write to logs. Never includes secrets. */
export function publicWebhookView(dest?: WebhookDest): {
  connected: boolean;
  url?: string;
  auth_mode?: AuthMode;
} {
  if (!dest) return { connected: false };
  return { connected: true, url: dest.url, auth_mode: dest.authMode };
}

export function redactSecrets(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const key = k.toLowerCase();
      if (
        key === "secret" ||
        key === "authorization" ||
        key === "webhook_secret" ||
        key === "recovery_secret" ||
        key === "token" ||
        key === "reset_token"
      ) {
        continue;
      }
      out[k] = redactSecrets(v);
    }
    return out;
  }
  return value;
}

export async function dispatchInboxNew(opts: {
  dest: WebhookDest;
  to: string;
  unread: number;
  now?: () => number;
  fetchImpl?: FetchLike;
  retries?: number;
  sleep?: (ms: number) => Promise<void>;
}): Promise<void> {
  const body: WakeBody = {
    event: "inbox.new",
    to: opts.to,
    unread: opts.unread,
  };
  const raw = JSON.stringify(body);
  const ts = Math.floor((opts.now?.() ?? Date.now()) / 1000).toString();
  const headers = webhookDispatchHeaders({
    authMode: opts.dest.authMode,
    timestamp: ts,
    rawBody: raw,
    hmacSecret: opts.dest.secret,
    authorization: opts.dest.authorization,
  });
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  const attempts = Math.max(1, opts.retries ?? 3);
  const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetchImpl(opts.dest.url, {
        method: "POST",
        headers,
        body: raw,
      });
      if (res.ok) return;
      lastErr = new Error(`webhook_status_${res.status}`);
    } catch (err) {
      lastErr = err;
    }
    if (i < attempts - 1) await sleep(BACKOFF_MS[i] ?? 16000);
  }
  throw lastErr instanceof Error ? lastErr : new Error("webhook_failed");
}
