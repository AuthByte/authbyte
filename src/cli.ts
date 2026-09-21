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

  latch claim <handle>              Create actor + write credentials
  latch recover <handle> --secret   Rotate token
  latch keygen                      Publish Ed25519 + age keys
  latch whoami                      GET /v0/handles/me
  latch invite [--note TEXT]        Mint a single-use invite
  latch redeem <token>              Mutual grant (no auto-mail)
  latch grants                      List peers + key_changed
  latch send <to> --body TEXT       Send a signed message
       [--intent message|status] [--priority low|normal|high] [--thread thr_…]
  latch inbox                       Headers only (no bodies)
  latch open <id>                   Open one envelope
  latch ack <id>                    Delete payload; print receipt
  latch notify <url> --secret S     Register HMAC webhook
  latch notify-clear                Disconnect webhook

Env: LATCH_URL  LATCH_CREDS
Credentials default: ./.latch.json or ~/.latch/credentials.json
`;
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
    const signing = generateSigning();
    const age = await generateAge();
    const creds: Creds = {
      url,
      handle: j.handle,
      actor_id: j.actor_id,
      token: j.token,
      recovery_secret: j.recovery_secret,
      signing_private_pem: signing.privatePem,
      signing_public_key: signing.publicWire,
      age_identity: age.identity,
      age_public_key: age.recipient,
    };
    saveCreds(creds);
    for (const [path, body] of [
      ["/v0/keys/signing", { public_key: signing.publicWire }],
      ["/v0/keys/age", { public_key: age.recipient }],
    ] as const) {
      const pub = await api(`${url}${path}`, "POST", creds.token, body);
      if (pub.status >= 400) show(pub.status, pub.json);
    }
    console.log(
      JSON.stringify(
        {
          actor_id: creds.actor_id,
          handle: creds.handle,
          creds: credsPath(),
          warning: "Token and recovery_secret stored in the creds file (mode 600). Do not paste them into chat.",
        },
        null,
        2,
      ),
    );
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
    const signing = existing?.signing_private_pem
      ? {
          privatePem: existing.signing_private_pem,
          publicWire: existing.signing_public_key,
        }
      : generateSigning();
    const creds: Creds = {
      url,
      handle: j.handle,
      actor_id: j.actor_id,
      token: j.token,
      recovery_secret: secret,
      signing_private_pem: signing.privatePem,
      signing_public_key: signing.publicWire,
      age_identity: existing?.age_identity,
      age_public_key: existing?.age_public_key,
    };
    saveCreds(creds);
    show(200, { actor_id: j.actor_id, handle: j.handle, creds: credsPath() });
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
    if (env.body && looksLikeAge(env.body) && creds.age_identity) {
      try {
        const plain = await ageDecrypt(creds.age_identity, env.body);
        console.log(
          JSON.stringify({ ...env, body: plain, enc: "age", decrypted: true }, null, 2),
        );
        return;
      } catch {
        console.error("age decrypt failed; printing ciphertext envelope");
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
    const secret = String(flags.secret ?? "");
    if (!hookUrl || !secret) die("usage: latch notify <url> --secret S");
    const r = await api(`${url}/v0/notifications`, "PUT", creds.token, {
      url: hookUrl,
      secret,
    });
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
