import { fromB64, sha256Hex, toB64 } from "./encoding";
import type { Keys } from "./keys";

const enc = new TextEncoder();

export type ManifestData = {
  id: string;
  version: number;
  name: string;
  size: number;
  sha256: string;
};

export type FilePackage = {
  meta: {
    id: string;
    owner: string;
    version: number;
    size?: number;
    manifest: string;
    manifest_signature: string;
    wrapped_dek: string;
  };
  blob: Uint8Array | ArrayBuffer;
};

function seenStorageKey(username: string): string {
  return `seen_versions_${username.trim().toLowerCase()}`;
}

function loadSeenVersions(username: string): Record<string, number> {
  try {
    return JSON.parse(localStorage.getItem(seenStorageKey(username)) ?? "{}") as Record<string, number>;
  } catch {
    return {};
  }
}

function saveSeenVersions(username: string, map: Record<string, number>): void {
  localStorage.setItem(seenStorageKey(username), JSON.stringify(map));
}

export function getSeenVersion(username: string, fileId: string): number {
  return loadSeenVersions(username)[fileId] ?? 0;
}

export function recordSeenVersion(username: string, fileId: string, version: number): void {
  const seen = loadSeenVersions(username);
  if (version > (seen[fileId] ?? 0)) {
    seen[fileId] = version;
    saveSeenVersions(username, seen);
  }
}

/** Verifica una firma ECDSA P-256 / SHA-256 (formato IEEE P1363) sobre el manifiesto JSON. */
export async function verifyManifestSignature(
  sigSpkiB64: string,
  manifest: string,
  signatureB64: string,
): Promise<boolean> {
  try {
    const pub = await crypto.subtle.importKey(
      "spki",
      fromB64(sigSpkiB64),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      fromB64(signatureB64),
      enc.encode(manifest),
    );
  } catch {
    return false;
  }
}

/** Genera una DEK AES-256-GCM aleatoria, cifra el archivo ligando (fileId|version) como AAD y antepone el IV. */
export async function encryptFile(
  fileId: string,
  version: number,
  data: Uint8Array,
): Promise<{ blob: Uint8Array; rawDek: Uint8Array }> {
  const rawDek = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const dataBuffer = Uint8Array.from(data);
  const dekKey = await crypto.subtle.importKey("raw", rawDek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(`${fileId}|${version}`) },
      dekKey,
      dataBuffer,
    ),
  );
  const blob = new Uint8Array(iv.length + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, iv.length);
  return { blob, rawDek };
}

/** Envuelve la DEK de 32 bytes con la clave pública RSA-OAEP del destinatario. */
export async function wrapDek(rawDek: Uint8Array, encPublic: CryptoKey): Promise<string> {
  const wrapped = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    encPublic,
    Uint8Array.from(rawDek),
  );
  return toB64(new Uint8Array(wrapped));
}

/**
 * Descarga verificada (HU-11):
 * 1. Verifica firma ECDSA del manifiesto
 * 2. Verifica correspondencia id/versión y defensa anti-rollback persistida
 * 3. Verifica SHA-256 del blob cifrado
 * 4. Desenvuelve DEK con RSA-OAEP y descifra AES-256-GCM con AAD (id|version)
 */
export async function verifyAndDecrypt(
  keys: Keys,
  pkg: FilePackage,
  ownerSigSpkiB64: string,
  username = "default",
): Promise<{ plain: Uint8Array; m: ManifestData }> {
  const { meta } = pkg;
  const blobBytes = pkg.blob instanceof Uint8Array ? pkg.blob : new Uint8Array(pkg.blob);

  const validSig = await verifyManifestSignature(ownerSigSpkiB64, meta.manifest, meta.manifest_signature);
  if (!validSig) {
    throw new Error("Firma del manifiesto inválida: metadatos alterados o clave no auténtica.");
  }

  const m = JSON.parse(meta.manifest) as ManifestData;
  if (m.id !== meta.id || m.version !== meta.version) {
    throw new Error("El manifiesto firmado no corresponde con el ID o versión reportados por el servidor.");
  }

  const lastSeen = getSeenVersion(username, meta.id);
  if (m.version < lastSeen) {
    throw new Error(`Rollback detectado: el servidor entregó v${m.version}, pero ya habías visto v${lastSeen}.`);
  }

  const actualHash = await sha256Hex(new Uint8Array(blobBytes));
  if (actualHash !== m.sha256) {
    throw new Error("El hash SHA-256 del archivo cifrado no coincide con el manifiesto firmado.");
  }

  const rawDek = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    keys.encPrivate,
    fromB64(meta.wrapped_dek),
  );
  const dekKey = await crypto.subtle.importKey("raw", rawDek, { name: "AES-GCM" }, false, ["decrypt"]);

  const iv = blobBytes.slice(0, 12);
  const ciphertext = blobBytes.slice(12);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(`${m.id}|${m.version}`) },
    dekKey,
    ciphertext,
  );

  recordSeenVersion(username, m.id, m.version);
  return { plain: new Uint8Array(plainBuf), m };
}