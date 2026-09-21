export const PROTOCOL = "latch";
export const WIRE_VERSION = 0;
export const BODY_PLAIN_CAP = 500;
export const BODY_AGE_BYTES = 8192;
export const UNREAD_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const INVITE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const WEBHOOK_SKEW_S = 300;
export const RETENTION_TTL_MIN = 3600;
export const RETENTION_TTL_MAX = 7_776_000;
export const HMAC_SECRET_MIN = 32;
export const AGE_ARMOR_HEAD = "-----BEGIN AGE ENCRYPTED FILE-----";

export const INTENTS = ["message", "status"] as const;
export type Intent = (typeof INTENTS)[number];

export const PRIORITIES = ["low", "normal", "high"] as const;
export type Priority = (typeof PRIORITIES)[number];

export type Envelope = {
  v: 0;
  id: string;
  from: string;
  to: string;
  intent: Intent;
  priority: Priority;
  thread_id?: string;
  body: string;
  blob_url?: string;
  sig: string;
};

export type EnvelopeUnsigned = Omit<Envelope, "sig">;

export type InboxHeader = {
  id: string;
  from: string;
  to: string;
  intent: Intent;
  priority: Priority;
  thread_id?: string;
  bytes: number;
  enc: "age" | "none";
  created_at: string;
};

export type Receipt = {
  id: string;
  from: string;
  to: string;
  acked_at?: string;
  expired_at?: string;
  bytes: number;
  status: "acked" | "expired";
};

export type GrantView = {
  grant_id: string;
  peer: { actor_id: string; handle: string };
  pinned_age_key?: string;
  pinned_signing_key?: string;
  status: "active" | "key_changed";
  created_at: string;
};

export function isIntent(v: unknown): v is Intent {
  return v === "message" || v === "status";
}

export function isPriority(v: unknown): v is Priority {
  return v === "low" || v === "normal" || v === "high";
}

export function isAgeArmored(body: string): boolean {
  return body.startsWith(AGE_ARMOR_HEAD);
}
