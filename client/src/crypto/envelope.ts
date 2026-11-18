/**
 * Cifrado de sobre y verificación al descargar (TK-05.1 / TK-11.2–11.4).
 * Implementación mínima para que el flujo de Cesar funcione de punta a punta.
 */
import type { Keys } from "./keys";
import { enc, fromB64, sha256Hex, toB64 } from "./encoding";
import { verifyText } from "./sign";

export type FilePackage = {
  meta: {
    id: string;
    owner: string;
    version: number;
    manifest: string;
    manifest_signature: string;
    wrapped_dek: string;
  };
  blob: Uint8Array;
};

const seenVersions = new Map<string, number>();

/** Cifra con DEK nueva; blob = IV(12) ‖ ciphertext ‖ tag; AD = "id|version". */
export async function encryptFile(
  id: string,
  version: number,
  data: Uint8Array,
): Promise<{ blob: Uint8Array; rawDek: ArrayBuffer }> {
  const rawDek = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const dek = await crypto.subtle.importKey("raw", rawDek, "AES-GCM", false, ["encrypt"]);
  const ad = enc.encode(`${id}|${version}`);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: ad }, dek, data),
  );
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv, 0);
  blob.set(ct, iv.length);
  return { blob, rawDek: rawDek.buffer };
}

export async function wrapDek(rawDek: ArrayBuffer, encPublic: CryptoKey): Promise<string> {
  return toB64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, encPublic, rawDek));
}

/**
 * Orden C4: firma del manifiesto → versión (anti-rollback) → SHA-256 del blob →
 * desenvolver DEK → AES-GCM.
 */
export async function verifyAndDecrypt(
  keys: Keys,
  pkg: FilePackage,
  ownerSigSpki: string,
): Promise<{ plain: Uint8Array; m: { id: string; version: number; name: string; size: number; sha256: string } }> {
  const { meta, blob } = pkg;
  const ok = await verifyText(ownerSigSpki, meta.manifest, meta.manifest_signature);
  if (!ok) throw new Error("Firma del manifiesto inválida");

  const m = JSON.parse(meta.manifest) as {
    id: string;
    version: number;
    name: string;
    size: number;
    sha256: string;
  };
  if (m.id !== meta.id || m.version !== meta.version) {
    throw new Error("El manifiesto no coincide con el id o la versión");
  }

  const last = seenVersions.get(meta.id) ?? 0;
  if (m.version < last) throw new Error("Rollback detectado: versión antigua");

  const hash = await sha256Hex(blob);
  if (hash !== m.sha256) throw new Error("El hash no coincide: archivo modificado");

  const rawDek = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    keys.encPrivate,
    fromB64(meta.wrapped_dek),
  );
  const dek = await crypto.subtle.importKey("raw", rawDek, "AES-GCM", false, ["decrypt"]);
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  const ad = enc.encode(`${m.id}|${m.version}`);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: ad }, dek, ct),
  );

  seenVersions.set(meta.id, m.version);
  return { plain, m };
}
