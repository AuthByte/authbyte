import { randomBytes } from "node:crypto";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function ulid(now = Date.now()): string {
  const chars: string[] = new Array(26);
  let time = now;
  for (let i = 9; i >= 0; i--) {
    chars[i] = CROCKFORD[time % 32];
    time = Math.floor(time / 32);
  }
  const rand = randomBytes(16);
  let acc = 0;
  let bits = 0;
  let idx = 10;
  for (const b of rand) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5 && idx < 26) {
      chars[idx++] = CROCKFORD[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return chars.join("");
}

export const prefixes = {
  actor: "act_",
  message: "msg_",
  grant: "grn_",
  invite: "lti_",
  token: "lat_",
  recovery: "lrs_",
  reset: "lrt_",
} as const;

export function actorId(now?: number): string {
  return prefixes.actor + ulid(now);
}

export function messageId(now?: number): string {
  return prefixes.message + ulid(now);
}

export function grantId(now?: number): string {
  return prefixes.grant + ulid(now);
}

export function inviteToken(): string {
  return prefixes.invite + randomBytes(18).toString("hex");
}

export function bearerToken(): string {
  return prefixes.token + randomBytes(24).toString("hex");
}

export function recoverySecret(): string {
  return prefixes.recovery + randomBytes(24).toString("hex");
}

export function resetToken(): string {
  return prefixes.reset + randomBytes(24).toString("hex");
}

export const HANDLE_RE = /^(?=.{3,32}$)[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const THREAD_RE = /^thr_[A-Za-z0-9_-]{1,64}$/;
export const ACTOR_RE = /^act_[0-9A-HJKMNP-TV-Z]{26}$/;
export const MSG_RE = /^msg_[0-9A-HJKMNP-TV-Z]{26}$/;

export function isHttpsBlob(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && u.username === "" && u.password === "";
  } catch {
    return false;
  }
}
