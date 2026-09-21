import { hmacSignature } from "./crypto.js";

export type WakeBody = {
  event: "inbox.new";
  to: string;
  unread: number;
};

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number }>;

const BACKOFF_MS = [1000, 4000, 16000];

export async function dispatchInboxNew(opts: {
  url: string;
  secret: string;
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
  const sig = hmacSignature(opts.secret, ts, raw);
  const headers = {
    "content-type": "application/json",
    "x-latch-event": "inbox.new",
    "x-latch-timestamp": ts,
    "x-latch-signature": sig,
  };
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  const attempts = Math.max(1, opts.retries ?? 3);
  const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetchImpl(opts.url, { method: "POST", headers, body: raw });
      if (res.ok) return;
      lastErr = new Error(`webhook_status_${res.status}`);
    } catch (err) {
      lastErr = err;
    }
    if (i < attempts - 1) await sleep(BACKOFF_MS[i] ?? 16000);
  }
  throw lastErr instanceof Error ? lastErr : new Error("webhook_failed");
}
