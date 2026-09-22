import {
  actorId,
  bearerToken,
  grantId,
  HANDLE_RE,
  inviteToken,
  recoverySecret,
  resetToken,
} from "./ids.js";
import { sha256hex } from "./crypto.js";
import {
  INVITE_TTL_MS,
  RESET_TTL_MS,
  UNREAD_TTL_MS,
  type AuthMode,
  type Envelope,
  type GrantView,
  type InboxHeader,
  type Intent,
  type Priority,
  type Receipt,
  isAgeArmored,
} from "./types.js";
import type { WebhookDest } from "./webhooks.js";

export type Retention = {
  enabled: boolean;
  ttl_seconds: number | null;
};

export type Actor = {
  actorId: string;
  handle: string;
  tokenHash: string;
  recoveryHash: string;
  agePublicKey?: string;
  signingPublicKey?: string;
  retention: Retention;
  createdAt: number;
  webhook?: WebhookDest;
};

export type Invite = {
  token: string;
  fromActorId: string;
  note?: string;
  expiresAt: number;
  redeemed: boolean;
};

export type Grant = {
  id: string;
  a: string;
  b: string;
  pinA: { age?: string; signing?: string };
  pinB: { age?: string; signing?: string };
  createdAt: number;
  revoked: boolean;
};

export type StoredMessage = {
  envelope: Envelope;
  queuedAt: number;
  expiresAt: number;
  openedAt?: number;
  ackedAt?: number;
  expiredAt?: number;
  bytes: number;
  status: "queued" | "opened" | "acked" | "expired";
  payload: string | null;
};

export type Clock = () => number;

export class MemoryStore {
  actors = new Map<string, Actor>();
  actorsByHandle = new Map<string, string>();
  actorsByTokenHash = new Map<string, string>();
  invites = new Map<string, Invite>();
  grants = new Map<string, Grant>();
  messages = new Map<string, StoredMessage>();
  /** from+id → message id */
  idempotency = new Map<string, string>();
  resetTickets = new Map<string, {
    tokenHash: string;
    handle: string;
    actorId: string;
    expiresAt: number;
    spent: boolean;
  }>();

  constructor(public now: Clock = () => Date.now()) {}

  claim(
    handle: string,
    recovery?: string,
  ): { actor: Actor; token: string; recovery_secret: string } {
    if (!HANDLE_RE.test(handle)) {
      throw Object.assign(new Error("invalid_handle"), { code: "invalid_handle" });
    }
    if (this.actorsByHandle.has(handle)) {
      throw Object.assign(new Error("handle_taken"), { code: "handle_taken" });
    }
    const token = bearerToken();
    const recovery_secret =
      recovery && recovery.length >= 16 ? recovery : recoverySecret();
    const id = actorId(this.now());
    const actor: Actor = {
      actorId: id,
      handle,
      tokenHash: sha256hex(token),
      recoveryHash: sha256hex(recovery_secret),
      retention: { enabled: false, ttl_seconds: null },
      createdAt: this.now(),
    };
    this.actors.set(id, actor);
    this.actorsByHandle.set(handle, id);
    this.actorsByTokenHash.set(actor.tokenHash, id);
    return { actor, token, recovery_secret };
  }

  recover(
    handle: string,
    secret: string,
  ): { actor: Actor; token: string } | null {
    const id = this.actorsByHandle.get(handle);
    if (!id) return null;
    const actor = this.actors.get(id);
    if (!actor) return null;
    if (sha256hex(secret) !== actor.recoveryHash) return null;
    this.actorsByTokenHash.delete(actor.tokenHash);
    const token = bearerToken();
    actor.tokenHash = sha256hex(token);
    this.actorsByTokenHash.set(actor.tokenHash, actor.actorId);
    return { actor, token };
  }

  byToken(token: string): Actor | undefined {
    const id = this.actorsByTokenHash.get(sha256hex(token));
    return id ? this.actors.get(id) : undefined;
  }

  byHandle(handle: string): Actor | undefined {
    const id = this.actorsByHandle.get(handle);
    return id ? this.actors.get(id) : undefined;
  }

  byId(id: string): Actor | undefined {
    return this.actors.get(id);
  }

  publishAge(actor: Actor, publicKey: string): void {
    if (!publicKey.startsWith("age1")) {
      throw Object.assign(new Error("invalid_age_key"), { code: "invalid_age_key" });
    }
    actor.agePublicKey = publicKey;
  }

  publishSigning(actor: Actor, publicKey: string): void {
    if (!publicKey.startsWith("ed25519:")) {
      throw Object.assign(new Error("invalid_signing_key"), {
        code: "invalid_signing_key",
      });
    }
    actor.signingPublicKey = publicKey;
  }

  createInvite(fromActorId: string, note?: string): Invite {
    const inv: Invite = {
      token: inviteToken(),
      fromActorId,
      note,
      expiresAt: this.now() + INVITE_TTL_MS,
      redeemed: false,
    };
    this.invites.set(inv.token, inv);
    return inv;
  }

  getInvite(token: string): Invite | undefined {
    return this.invites.get(token);
  }

  pairKey(a: string, b: string): string {
    return a < b ? `${a}:${b}` : `${b}:${a}`;
  }

  findGrant(a: string, b: string): Grant | undefined {
    const g = this.grants.get(this.pairKey(a, b));
    if (!g || g.revoked) return undefined;
    return g;
  }

  redeem(token: string, redeemer: Actor): Grant {
    const inv = this.invites.get(token);
    if (!inv) {
      throw Object.assign(new Error("unknown_invite"), { code: "unknown_invite" });
    }
    if (inv.redeemed) {
      throw Object.assign(new Error("invite_spent"), { code: "invite_spent" });
    }
    if (inv.expiresAt <= this.now()) {
      throw Object.assign(new Error("invite_expired"), { code: "invite_expired" });
    }
    if (inv.fromActorId === redeemer.actorId) {
      throw Object.assign(new Error("self_redeem"), { code: "self_redeem" });
    }
    const issuer = this.actors.get(inv.fromActorId);
    if (!issuer) {
      throw Object.assign(new Error("unknown_invite"), { code: "unknown_invite" });
    }
    if (this.findGrant(issuer.actorId, redeemer.actorId)) {
      throw Object.assign(new Error("already_granted"), { code: "already_granted" });
    }
    inv.redeemed = true;
    const [a, b] =
      issuer.actorId < redeemer.actorId
        ? [issuer, redeemer]
        : [redeemer, issuer];
    const grant: Grant = {
      id: grantId(this.now()),
      a: a.actorId,
      b: b.actorId,
      pinA: { age: a.agePublicKey, signing: a.signingPublicKey },
      pinB: { age: b.agePublicKey, signing: b.signingPublicKey },
      createdAt: this.now(),
      revoked: false,
    };
    this.grants.set(this.pairKey(grant.a, grant.b), grant);
    return grant;
  }

  peerKeyChanged(grant: Grant, peerId: string): boolean {
    const peer = this.actors.get(peerId);
    if (!peer) return true;
    const pin = peerId === grant.a ? grant.pinA : grant.pinB;
    return pin.age !== peer.agePublicKey || pin.signing !== peer.signingPublicKey;
  }

  grantView(grant: Grant, viewerId: string): GrantView {
    const peerId = grant.a === viewerId ? grant.b : grant.a;
    const peer = this.actors.get(peerId);
    const pin = peerId === grant.a ? grant.pinA : grant.pinB;
    return {
      grant_id: grant.id,
      peer: {
        actor_id: peerId,
        handle: peer?.handle ?? "unknown",
      },
      pinned_age_key: pin.age,
      pinned_signing_key: pin.signing,
      status: this.peerKeyChanged(grant, peerId) ? "key_changed" : "active",
      created_at: new Date(grant.createdAt).toISOString(),
    };
  }

  listGrants(viewerId: string): GrantView[] {
    const out: GrantView[] = [];
    for (const g of this.grants.values()) {
      if (g.revoked) continue;
      if (g.a !== viewerId && g.b !== viewerId) continue;
      out.push(this.grantView(g, viewerId));
    }
    return out.sort((x, y) => x.created_at.localeCompare(y.created_at));
  }

  grantById(id: string, viewerId: string): Grant | undefined {
    for (const g of this.grants.values()) {
      if (g.id === id && !g.revoked && (g.a === viewerId || g.b === viewerId)) {
        return g;
      }
    }
    return undefined;
  }

  repin(grant: Grant, viewerId: string): void {
    const peerId = grant.a === viewerId ? grant.b : grant.a;
    const peer = this.actors.get(peerId);
    if (!peer) return;
    const pin = { age: peer.agePublicKey, signing: peer.signingPublicKey };
    if (peerId === grant.a) grant.pinA = pin;
    else grant.pinB = pin;
  }

  revoke(grant: Grant): void {
    grant.revoked = true;
  }

  expireDue(): void {
    const t = this.now();
    for (const m of this.messages.values()) {
      if (m.status === "queued" || m.status === "opened") {
        if (m.expiresAt <= t) {
          m.status = "expired";
          m.expiredAt = t;
          m.payload = null;
          m.envelope = { ...m.envelope, body: "" };
        }
      }
    }
  }

  enqueue(envelope: Envelope): { message: StoredMessage; replayed: boolean } {
    this.expireDue();
    const key = `${envelope.from}:${envelope.id}`;
    const existingId = this.idempotency.get(key);
    if (existingId) {
      const existing = this.messages.get(existingId);
      if (!existing) throw new Error("idempotency_orphan");
      const same =
        existing.envelope.body === envelope.body &&
        existing.envelope.to === envelope.to &&
        existing.envelope.intent === envelope.intent &&
        existing.envelope.priority === envelope.priority &&
        existing.envelope.thread_id === envelope.thread_id &&
        existing.envelope.blob_url === envelope.blob_url &&
        existing.envelope.sig === envelope.sig;
      if (!same) {
        throw Object.assign(new Error("idempotency_conflict"), {
          code: "idempotency_conflict",
        });
      }
      return { message: existing, replayed: true };
    }
    const bytes = Buffer.byteLength(envelope.body, "utf8");
    const stored: StoredMessage = {
      envelope,
      queuedAt: this.now(),
      expiresAt: this.now() + UNREAD_TTL_MS,
      bytes,
      status: "queued",
      payload: envelope.body,
    };
    this.messages.set(envelope.id, stored);
    this.idempotency.set(key, envelope.id);
    return { message: stored, replayed: false };
  }

  unreadCount(actorId: string): number {
    this.expireDue();
    let n = 0;
    for (const m of this.messages.values()) {
      if (m.envelope.to === actorId && (m.status === "queued" || m.status === "opened")) {
        n++;
      }
    }
    return n;
  }

  headers(actorId: string): InboxHeader[] {
    this.expireDue();
    const rows: InboxHeader[] = [];
    for (const m of this.messages.values()) {
      if (m.envelope.to !== actorId) continue;
      if (m.status !== "queued" && m.status !== "opened") continue;
      const env = m.envelope;
      rows.push({
        id: env.id,
        from: env.from,
        to: env.to,
        intent: env.intent as Intent,
        priority: env.priority as Priority,
        thread_id: env.thread_id,
        bytes: m.bytes,
        enc: isAgeArmored(m.payload ?? "") ? "age" : "none",
        created_at: new Date(m.queuedAt).toISOString(),
      });
    }
    return rows.sort((a, b) => a.created_at.localeCompare(b.created_at)).slice(0, 100);
  }

  open(actorId: string, id: string): StoredMessage | "gone" | "missing" {
    this.expireDue();
    const m = this.messages.get(id);
    if (!m || m.envelope.to !== actorId) return "missing";
    if (m.status === "acked" || m.status === "expired" || m.payload === null) {
      return "gone";
    }
    if (m.status === "queued") {
      m.status = "opened";
      m.openedAt = this.now();
    }
    return m;
  }

  ack(actorId: string, id: string): Receipt | "missing" {
    this.expireDue();
    const m = this.messages.get(id);
    if (!m || m.envelope.to !== actorId) return "missing";
    if (m.status === "expired") {
      return this.receipt(m);
    }
    if (m.status === "acked") {
      return this.receipt(m);
    }
    const actor = this.actors.get(actorId);
    const retain =
      actor?.retention.enabled &&
      actor.retention.ttl_seconds &&
      actor.retention.ttl_seconds > 0;
    m.status = "acked";
    m.ackedAt = this.now();
    if (!retain) {
      m.payload = null;
      m.envelope = { ...m.envelope, body: "" };
    }
    return this.receipt(m);
  }

  receipt(m: StoredMessage): Receipt {
    return {
      id: m.envelope.id,
      from: m.envelope.from,
      to: m.envelope.to,
      acked_at: m.ackedAt ? new Date(m.ackedAt).toISOString() : undefined,
      expired_at: m.expiredAt ? new Date(m.expiredAt).toISOString() : undefined,
      bytes: m.bytes,
      status: m.status === "expired" ? "expired" : "acked",
    };
  }

  setWebhook(actor: Actor, dest: WebhookDest): void {
    actor.webhook = dest;
  }

  clearWebhook(actor: Actor): void {
    delete actor.webhook;
  }

  issueReset(handle: string): { actor: Actor; reset_token: string; expires_at: number } {
    const actor = this.byHandle(handle);
    if (!actor) {
      throw Object.assign(new Error("not_found"), { code: "not_found" });
    }
    const raw = resetToken();
    const expiresAt = this.now() + RESET_TTL_MS;
    this.resetTickets.set(sha256hex(raw), {
      tokenHash: sha256hex(raw),
      handle: actor.handle,
      actorId: actor.actorId,
      expiresAt,
      spent: false,
    });
    return { actor, reset_token: raw, expires_at: expiresAt };
  }

  reclaim(handle: string, resetRaw: string): { actor: Actor; token: string; recovery_secret: string } | null {
    const ticket = this.resetTickets.get(sha256hex(resetRaw));
    if (!ticket || ticket.spent) return null;
    if (ticket.expiresAt <= this.now()) return null;
    if (ticket.handle !== handle) return null;
    const actor = this.actors.get(ticket.actorId);
    if (!actor) return null;
    this.actorsByTokenHash.delete(actor.tokenHash);
    const token = bearerToken();
    const recovery_secret = recoverySecret();
    actor.tokenHash = sha256hex(token);
    actor.recoveryHash = sha256hex(recovery_secret);
    this.actorsByTokenHash.set(actor.tokenHash, actor.actorId);
    delete actor.webhook;
    ticket.spent = true;
    return { actor, token, recovery_secret };
  }

  deleteHandle(handle: string): boolean {
    const actor = this.byHandle(handle);
    if (!actor) return false;
    this.actorsByTokenHash.delete(actor.tokenHash);
    this.actorsByHandle.delete(actor.handle);
    this.actors.delete(actor.actorId);
    for (const [key, g] of this.grants) {
      if (g.a === actor.actorId || g.b === actor.actorId) {
        g.revoked = true;
        this.grants.delete(key);
      }
    }
    return true;
  }

  listAgentsPublic(): Array<{
    handle: string;
    actor_id: string;
    webhook_connected: boolean;
    webhook_url?: string;
    auth_mode?: AuthMode;
    age_published: boolean;
    signing_published: boolean;
    keys_ready: boolean;
  }> {
    return [...this.actors.values()]
      .sort((a, b) => a.handle.localeCompare(b.handle))
      .map((a) => ({
        handle: a.handle,
        actor_id: a.actorId,
        webhook_connected: Boolean(a.webhook),
        webhook_url: a.webhook?.url,
        auth_mode: a.webhook?.authMode,
        age_published: Boolean(a.agePublicKey),
        signing_published: Boolean(a.signingPublicKey),
        keys_ready: Boolean(a.agePublicKey && a.signingPublicKey),
      }));
  }
}

export function codeOf(err: unknown): string | undefined {
  if (err && typeof err === "object" && "code" in err) {
    return String((err as { code: string }).code);
  }
  return undefined;
}
