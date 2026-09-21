import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import * as age from "age-encryption";
import { AGE_ARMOR_HEAD } from "./types.js";

export function sha256hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

export function fingerprint(publicKey: string): string {
  const hex = sha256hex(publicKey).slice(0, 16);
  return hex.match(/.{4}/g)!.join("-");
}

export function generateSigning(): { publicWire: string; privatePem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x) throw new Error("ed25519 jwk missing x");
  return {
    publicWire: `ed25519:${jwk.x}`,
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export function signCanonical(privatePem: string, canonical: string): string {
  const key = createPrivateKey(privatePem);
  return sign(null, Buffer.from(canonical, "utf8"), key).toString("base64url");
}

export function verifyCanonical(
  publicWire: string,
  canonical: string,
  sig: string,
): boolean {
  try {
    const x = publicWire.startsWith("ed25519:")
      ? publicWire.slice("ed25519:".length)
      : publicWire;
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x },
      format: "jwk",
    });
    return verify(
      null,
      Buffer.from(canonical, "utf8"),
      key,
      Buffer.from(sig, "base64url"),
    );
  } catch {
    return false;
  }
}

export function hmacSignature(
  secret: string,
  timestamp: string,
  rawBody: string,
): string {
  const mac = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  return `sha256=${mac}`;
}

export function hmacValid(
  secret: string,
  timestamp: string,
  rawBody: string,
  header: string,
): boolean {
  const expected = Buffer.from(hmacSignature(secret, timestamp, rawBody));
  const got = Buffer.from(header);
  if (expected.length !== got.length) return false;
  return timingSafeEqual(expected, got);
}

export async function generateAge(): Promise<{
  identity: string;
  recipient: string;
}> {
  const identity = await age.generateIdentity();
  const recipient = await age.identityToRecipient(identity);
  return { identity, recipient };
}

export async function ageEncrypt(
  recipient: string,
  plaintext: string,
): Promise<string> {
  const encrypter = new age.Encrypter();
  encrypter.addRecipient(recipient);
  const ct = await encrypter.encrypt(plaintext);
  return age.armor.encode(ct);
}

export async function ageDecrypt(
  identity: string,
  armored: string,
): Promise<string> {
  const decrypter = new age.Decrypter();
  decrypter.addIdentity(identity);
  const decoded = age.armor.decode(armored);
  const out = await decrypter.decrypt(decoded, "text");
  return typeof out === "string" ? out : new TextDecoder().decode(out);
}

export function looksLikeAge(body: string): boolean {
  return body.startsWith(AGE_ARMOR_HEAD);
}

export function randomSecret(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function scalarLength(s: string): number {
  return [...s].length;
}
