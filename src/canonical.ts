import type { EnvelopeUnsigned } from "./types.js";

/** Canonical bytes for Ed25519 envelope signatures. Key order is part of the wire. */
export function canonicalEnvelope(env: EnvelopeUnsigned): string {
  const o: Record<string, unknown> = {
    v: env.v,
    id: env.id,
    from: env.from,
    to: env.to,
    intent: env.intent,
    priority: env.priority,
  };
  if (env.thread_id !== undefined) o.thread_id = env.thread_id;
  o.body = env.body;
  if (env.blob_url !== undefined) o.blob_url = env.blob_url;
  return JSON.stringify(o);
}
