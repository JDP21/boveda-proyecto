import { api } from "../api";
import { canonicalJSON, fromB64, fromHex, sha256Hex } from "../crypto/encoding";
import type { Keys } from "../crypto/keys";
import { signText } from "../crypto/sign";

export const GENESIS_HASH = "0".repeat(64);
const enc = new TextEncoder();

export type AuditPayload = {
  event: string;
  prev_hash: string;
  entry_hash: string;
  signature: string;
};

export type AuditRecord = AuditPayload & {
  seq: number;
  actor: string;
  signer_key: string;
  created_at: string;
};

export type ChainVerificationResult =
  | { ok: true; count: number }
  | { ok: false; brokenAt: number; reason: "prev_hash" | "entry_hash" | "signature" };

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function computeEntryHash(prevHash: string, eventJson: string): Promise<string> {
  return sha256Hex(concatBytes(fromHex(prevHash), enc.encode(eventJson)) as BufferSource);
}

async function verifyEcdsaText(spkiB64: string, text: string, sigB64: string): Promise<boolean> {
  try {
    const pub = await crypto.subtle.importKey(
      "spki",
      fromB64(spkiB64) as BufferSource,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      fromB64(sigB64) as BufferSource,
      enc.encode(text),
    );
  } catch {
    return false;
  }
}

export async function buildAuditEntry(
  keys: Keys,
  eventObj: Record<string, unknown>,
): Promise<AuditPayload> {
  const head = await api<{ seq: number; hash: string }>("GET", "/audit/head");
  const event = canonicalJSON({ ...eventObj, ts: new Date().toISOString() });
  const entry_hash = await computeEntryHash(head.hash, event);
  const signature = await signText(keys.sigPrivate, entry_hash);
  return { event, prev_hash: head.hash, entry_hash, signature };
}

export async function logAudit(
  keys: Keys,
  eventObj: Record<string, unknown>,
  retries = 2,
): Promise<void> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const payload = await buildAuditEntry(keys, eventObj);
    try {
      await api("POST", "/audit", payload);
      return;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.startsWith("409:") && attempt < retries) continue;
      throw err;
    }
  }
}

export async function fetchAuditLog(): Promise<AuditRecord[]> {
  return api<AuditRecord[]>("GET", "/audit");
}

export async function verifyFullAuditChain(
  entries: AuditRecord[],
): Promise<ChainVerificationResult> {
  let expectedPrev = GENESIS_HASH;
  for (const entry of entries) {
    if (entry.prev_hash !== expectedPrev) {
      return { ok: false, brokenAt: entry.seq, reason: "prev_hash" };
    }
    const recalculated = await computeEntryHash(expectedPrev, entry.event);
    if (recalculated !== entry.entry_hash) {
      return { ok: false, brokenAt: entry.seq, reason: "entry_hash" };
    }
    const validSig = await verifyEcdsaText(entry.signer_key, entry.entry_hash, entry.signature);
    if (!validSig) {
      return { ok: false, brokenAt: entry.seq, reason: "signature" };
    }
    expectedPrev = entry.entry_hash;
  }
  return { ok: true, count: entries.length };
}