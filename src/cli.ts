#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { canonicalEnvelope } from "./canonical.js";
import {
  ageDecrypt,
  ageEncrypt,
  generateAge,
  generateSigning,
  looksLikeAge,
  signCanonical,
} from "./crypto.js";
import { messageId } from "./ids.js";
import type { Envelope, Intent, Priority } from "./types.js";

type Creds = {
  url: string;
  handle: string;
  actor_id: string;
  token: string;
  recovery_secret: string;
  signing_private_pem: string;
  signing_public_key: string;
  age_identity?: string;
  age_public_key?: string;
};

function credsPath(): string {
  if (process.env.LATCH_CREDS) return process.env.LATCH_CREDS;
  const local = join(process.cwd(), ".latch.json");
  if (existsSync(local)) return local;
  return join(homedir(), ".latch", "credentials.json");
}

function loadCreds(): Creds {
  const p = credsPath();
  if (!existsSync(p)) {
    die(`No credentials at ${p}. Run: latch claim <handle>`);
  }
  return JSON.parse(readFileSync(p, "utf8")) as Creds;
}

function saveCreds(creds: Creds): void {
  const p = credsPath();
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(creds, null, 2), { mode: 0o600 });
}

function baseUrl(creds?: Partial<Creds>): string {
  return (
    process.env.LATCH_URL ??
    creds?.url ??
    "http://127.0.0.1:8787"
  ).replace(/\/$/, "");
}

function die(msg: string, code = 1): never {
  console.error(msg);
  process.exit(code);
}

function parseArgs(argv: string[]): { cmd: string; pos: string[]; flags: Record<string, string | boolean> } {
  const [cmd = "help", ...rest] = argv;
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const name = a.slice(2);
      const next = rest[i + 1];
      if (next === undefined || next.startsWith("--")) flags[name] = true;
      else {
        flags[name] = next;
        i++;
      }
    } else pos.push(a);
  }
  return { cmd, pos, flags };
}

async function api(
  url: string,
  method: string,
  token?: string,
  body?: unknown,
): Promise<{ status: number; json: unknown }> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
  }
  return { status: res.status, json };
}

function show(status: number, json: unknown): void {
  if (status >= 400) {
    console.error(JSON.stringify(json, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify(json, null, 2));
}

async function resolveActor(creds: Creds, to: string): Promise<string> {
  if (to.startsWith("act_")) return to;
  const { status, json } = await api(
    `${baseUrl(creds)}/v0/handles/${encodeURIComponent(to)}`,
    "GET",
  );
  if (status !== 200 || !json || typeof json !== "object" || !("actor_id" in json)) {
    die(`Unknown handle ${to}`);
  }
  return String((json as { actor_id: string }).actor_id);
}

function help(): string {
  return `Latch v0 — grant-latched agent mail (communication only)

  latch claim <handle>              Create actor; persist secrets; publish keys
  latch join <handle>               Claim + optional Grok/HMAC webhook in one step
       --webhook-url URL
       [--auth-mode hmac|authorization|both]
       [--secret HMAC] [--authorization "Bearer …"]
       [--join-code CODE]
  latch recover <handle> --secret   Rotate token with recovery secret
  latch reclaim <handle> --reset-token
                                    Operator-issued one-time reclaim (clears webhook)
  latch keygen                      Publish Ed25519 + age keys
  latch whoami                      GET /v0/handles/me
  latch invite [--note TEXT]        Mint a single-use invite
  latch redeem <token>              Mutual grant (no auto-mail)
  latch grants                      List peers + key_changed
  latch send <to> --body TEXT       Send a signed, E2E-ready message
  latch inbox                       Headers only (no bodies)
  latch open <id>                   Open one envelope
  latch ack <id>                    Delete payload; print receipt
  latch notify <url>                Register wake destination
       --auth-mode hmac|authorization|both
       [--secret HMAC] [--authorization "Bearer …"]
  latch notify-clear                Disconnect webhook

Env: LATCH_URL  LATCH_CREDS  LATCH_OPS_SECRET (server)  LATCH_JOIN_CODE (server)
Credentials default: ./.latch.json or ~/.latch/credentials.json
Never paste tokens, recovery secrets, or Authorization headers into chat.
`;
}

function keysReady(creds: Creds): boolean {
  return Boolean(
    creds.signing_private_pem &&
      creds.signing_public_key &&
      creds.age_identity &&
      creds.age_public_key,
  );
}

async function persistThenPublishKeys(
  url: string,
  base: Pick<Creds, "handle" | "actor_id" | "token" | "recovery_secret"> &
    Partial<Creds>,
): Promise<Creds> {
  const first: Creds = {
    url,
    handle: base.handle,
    actor_id: base.actor_id,
    token: base.token,
    recovery_secret: base.recovery_secret,
    signing_private_pem: base.signing_private_pem ?? "",
    signing_public_key: base.signing_public_key ?? "",
    age_identity: base.age_identity,
    age_public_key: base.age_public_key,
  };
  saveCreds(first);

  const signing =
    first.signing_private_pem && first.signing_public_key
      ? { privatePem: first.signing_private_pem, publicWire: first.signing_public_key }
      : generateSigning();
  const age =
    first.age_identity && first.age_public_key
      ? { identity: first.age_identity, recipient: first.age_public_key }
      : await generateAge();

  const creds: Creds = {
    ...first,
    signing_private_pem: signing.privatePem,
    signing_public_key: signing.publicWire,
    age_identity: age.identity,
    age_public_key: age.recipient,
  };
  saveCreds(creds);

  for (const [path, body] of [
    ["/v0/keys/signing", { public_key: creds.signing_public_key }],
    ["/v0/keys/age", { public_key: creds.age_public_key }],
  ] as const) {
    const pub = await api(`${url}${path}`, "POST", creds.token, body);
    if (pub.status >= 400) show(pub.status, pub.json);
  }

  const me = await api(`${url}/v0/handles/me`, "GET", creds.token);
  const j = me.json as {
    signing_public_key?: string | null;
    age_public_key?: string | null;
    keys_ready?: boolean;
  };
  if (
    me.status >= 400 ||
    j.signing_public_key !== creds.signing_public_key ||
    j.age_public_key !== creds.age_public_key ||
    j.keys_ready !== true
  ) {
    die("Published keys did not verify. Secrets are already on disk; retry latch keygen.");
  }
  return creds;
}

function successCreds(creds: Creds, extra?: Record<string, unknown>): void {
  console.log(
    JSON.stringify(
      {
        actor_id: creds.actor_id,
        handle: creds.handle,
        creds: credsPath(),
        keys_ready: true,
        warning:
          "Token, recovery_secret, and key material stored locally (mode 600). Do not paste them into chat.",
        ...extra,
      },
      null,
      2,
    ),
  );
}

async function main(): Promise<void> {
  const { cmd, pos, flags } = parseArgs(process.argv.slice(2));

  if (cmd === "help" || cmd === "-h" || cmd === "--help") {
    console.log(help());
    return;
  }

  if (cmd === "claim") {
    const handle = pos[0];
    if (!handle) die("usage: latch claim <handle>");
    const url = baseUrl();
    const { status, json } = await api(`${url}/v0/handles/claim`, "POST", undefined, {
      handle,
    });
    if (status >= 400) {
      show(status, json);
      return;
    }
    const j = json as {
      actor_id: string;
      handle: string;
      token: string;
      recovery_secret: string;
    };
    const creds = await persistThenPublishKeys(url, j);
    successCreds(creds);
    return;
  }

  if (cmd === "join") {
    const handle = pos[0];
    if (!handle) die("usage: latch join <handle> --webhook-url URL [--auth-mode authorization] …");
    const url = baseUrl();
    const webhookUrl = typeof flags["webhook-url"] === "string" ? flags["webhook-url"] : undefined;
    const body: Record<string, string> = { handle };
    if (webhookUrl) body.webhook_url = webhookUrl;
    if (typeof flags["auth-mode"] === "string") body.webhook_auth_mode = flags["auth-mode"];
    if (typeof flags.secret === "string") body.webhook_secret = flags.secret;
    if (typeof flags.authorization === "string") {
      body.webhook_authorization = flags.authorization;
    }
    if (typeof flags["join-code"] === "string") body.join_code = flags["join-code"];
    const { status, json } = await api(`${url}/v0/join`, "POST", undefined, body);
    if (status >= 400) {
      show(status, json);
      return;
    }
    const j = json as {
      actor_id: string;
      handle: string;
      token: string;
      recovery_secret: string;
    };
    const creds = await persistThenPublishKeys(url, j);
    successCreds(creds, { webhook: (json as { webhook?: unknown }).webhook });
    return;
  }

  if (cmd === "recover") {
    const handle = pos[0];
    const secret = String(flags.secret ?? "");
    if (!handle || !secret) die("usage: latch recover <handle> --secret lrs_…");
    const url = baseUrl();
    const { status, json } = await api(`${url}/v0/handles/recover`, "POST", undefined, {
      handle,
      recovery_secret: secret,
    });
    if (status >= 400) {
      show(status, json);
      return;
    }
    const j = json as { actor_id: string; handle: string; token: string };
    const existing = existsSync(credsPath()) ? loadCreds() : null;
    const creds = await persistThenPublishKeys(url, {
      handle: j.handle,
      actor_id: j.actor_id,
      token: j.token,
      recovery_secret: secret,
      signing_private_pem: existing?.signing_private_pem,
      signing_public_key: existing?.signing_public_key,
      age_identity: existing?.age_identity,
      age_public_key: existing?.age_public_key,
    });
    successCreds(creds);
    return;
  }

  if (cmd === "reclaim") {
    const handle = pos[0];
    const reset = String(flags["reset-token"] ?? "");
    if (!handle || !reset) die("usage: latch reclaim <handle> --reset-token lrt_…");
    const url = baseUrl();
    const { status, json } = await api(`${url}/v0/handles/reclaim`, "POST", undefined, {
      handle,
      reset_token: reset,
    });
    if (status >= 400) {
      show(status, json);
      return;
    }
    const j = json as {
      actor_id: string;
      handle: string;
      token: string;
      recovery_secret: string;
    };
    const creds = await persistThenPublishKeys(url, j);
    successCreds(creds, { webhook_cleared: true });
    return;
  }

  const creds = loadCreds();
  const url = baseUrl(creds);

  if (cmd === "keygen") {
    const signing = generateSigning();
    const age = await generateAge();
    creds.signing_private_pem = signing.privatePem;
    creds.signing_public_key = signing.publicWire;
    creds.age_identity = age.identity;
    creds.age_public_key = age.recipient;
    const a = await api(`${url}/v0/keys/signing`, "POST", creds.token, {
      public_key: signing.publicWire,
    });
    if (a.status >= 400) show(a.status, a.json);
    const b = await api(`${url}/v0/keys/age`, "POST", creds.token, {
      public_key: age.recipient,
    });
    if (b.status >= 400) show(b.status, b.json);
    saveCreds(creds);
    console.log(
      JSON.stringify(
        {
          signing_public_key: signing.publicWire,
          age_public_key: age.recipient,
          note: "Existing grants may now be key_changed until peers repin.",
        },
        null,
        2,
      ),
    );
    return;
  }

  if (cmd === "whoami") {
    const r = await api(`${url}/v0/handles/me`, "GET", creds.token);
    show(r.status, r.json);
    return;
  }

  if (cmd === "invite") {
    const note = typeof flags.note === "string" ? flags.note : undefined;
    const r = await api(`${url}/v0/invites`, "POST", creds.token, note ? { note } : {});
    show(r.status, r.json);
    return;
  }

  if (cmd === "redeem") {
    const token = pos[0];
    if (!token) die("usage: latch redeem <token>");
    const r = await api(
      `${url}/v0/invites/${encodeURIComponent(token)}/redeem`,
      "POST",
      creds.token,
    );
    show(r.status, r.json);
    return;
  }

  if (cmd === "grants") {
    const r = await api(`${url}/v0/grants`, "GET", creds.token);
    show(r.status, r.json);
    return;
  }

  if (cmd === "send") {
    const toArg = pos[0];
    const text = typeof flags.body === "string" ? flags.body : "";
    if (!toArg || !text) die("usage: latch send <handle|act_…> --body TEXT");
    if (!keysReady(creds)) {
      die("keys_required: run latch keygen and confirm whoami.keys_ready before sending.");
    }
    const me = await api(`${url}/v0/handles/me`, "GET", creds.token);
    const ready = (me.json as { keys_ready?: boolean }).keys_ready;
    if (me.status >= 400 || ready !== true) {
      die("keys_required: published age + Ed25519 keys were not verified.");
    }
    const to = await resolveActor(creds, toArg);
    const grants = await api(`${url}/v0/grants`, "GET", creds.token);
    const list = (grants.json as { grants?: Array<{
      peer: { actor_id: string };
      status: string;
      pinned_age_key?: string;
    }> }).grants ?? [];
    const g = list.find((x) => x.peer.actor_id === to);
    if (!g) die("no_grant: exchange an invite first.");
    if (g.status === "key_changed") {
      die("key_changed: halt. Re-verify fingerprints out of band, then repin.");
    }
    let body = text;
    if (g.pinned_age_key) {
      body = await ageEncrypt(g.pinned_age_key, text);
    }
    const intent = (typeof flags.intent === "string" ? flags.intent : "message") as Intent;
    const priority = (typeof flags.priority === "string" ? flags.priority : "normal") as Priority;
    const thread_id = typeof flags.thread === "string" ? flags.thread : undefined;
    const unsigned = {
      v: 0 as const,
      id: messageId(),
      from: creds.actor_id,
      to,
      intent,
      priority,
      thread_id,
      body,
    };
    const sig = signCanonical(creds.signing_private_pem, canonicalEnvelope(unsigned));
    const envelope: Envelope = { ...unsigned, sig };
    const r = await api(`${url}/v0/messages`, "POST", creds.token, envelope);
    show(r.status, r.json);
    return;
  }

  if (cmd === "inbox") {
    const r = await api(`${url}/v0/inbox/headers`, "GET", creds.token);
    show(r.status, r.json);
    return;
  }

  if (cmd === "open") {
    const id = pos[0];
    if (!id) die("usage: latch open <id>");
    const r = await api(
      `${url}/v0/inbox/${encodeURIComponent(id)}`,
      "GET",
      creds.token,
    );
    if (r.status >= 400) {
      show(r.status, r.json);
      return;
    }
    const env = r.json as { body?: string };
    if (env.body && looksLikeAge(env.body)) {
      if (!creds.age_identity) {
        die("No local age identity. Reclaim/keygen before opening ciphertext.");
      }
      try {
        const plain = await ageDecrypt(creds.age_identity, env.body);
        console.log(
          JSON.stringify({ ...env, body: plain, enc: "age", decrypted: true }, null, 2),
        );
        return;
      } catch {
        die("age decrypt failed. Ciphertext not printed. Do not retry with another key.");
      }
    }
    show(r.status, r.json);
    return;
  }

  if (cmd === "ack") {
    const id = pos[0];
    if (!id) die("usage: latch ack <id>");
    const r = await api(
      `${url}/v0/inbox/${encodeURIComponent(id)}/ack`,
      "POST",
      creds.token,
    );
    show(r.status, r.json);
    return;
  }

  if (cmd === "notify") {
    const hookUrl = pos[0];
    if (!hookUrl) {
      die("usage: latch notify <url> --auth-mode hmac|authorization|both [--secret S] [--authorization HEADER]");
    }
    const payload: Record<string, string> = { url: hookUrl };
    if (typeof flags["auth-mode"] === "string") payload.auth_mode = flags["auth-mode"];
    if (typeof flags.secret === "string") payload.secret = flags.secret;
    if (typeof flags.authorization === "string") payload.authorization = flags.authorization;
    const r = await api(`${url}/v0/notifications`, "PUT", creds.token, payload);
    show(r.status, r.json);
    return;
  }

  if (cmd === "notify-clear") {
    const r = await api(`${url}/v0/notifications`, "DELETE", creds.token);
    show(r.status, r.json);
    return;
  }

  die(help(), 1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
