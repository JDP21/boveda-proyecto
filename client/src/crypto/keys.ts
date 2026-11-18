/**
 * Generación / desbloqueo de claves (HU-04).
 * Necesario para que el flujo del cliente funcione; Camilo puede refinar aquí.
 */
import { argon2id } from "hash-wasm";
import { api } from "../api";
import { enc, fromB64, toB64 } from "./encoding";

export type Keys = {
  encPrivate: CryptoKey;
  encPublic: CryptoKey;
  sigPrivate: CryptoKey;
  sigPublic: CryptoKey;
  encSpki: string;
  sigSpki: string;
};

const ARGON2 = { alg: "argon2id" as const, m: 65536, t: 3, p: 1 };
const WRAP_AD = enc.encode("user-private-keys");

async function deriveKek(phrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const raw = await argon2id({
    password: phrase,
    salt,
    parallelism: ARGON2.p,
    iterations: ARGON2.t,
    memorySize: ARGON2.m,
    hashLength: 32,
    outputType: "binary",
  });
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function exportSpki(key: CryptoKey) {
  return toB64(await crypto.subtle.exportKey("spki", key));
}

async function exportPkcs8(key: CryptoKey) {
  return toB64(await crypto.subtle.exportKey("pkcs8", key));
}

/** Primera vez: genera RSA-OAEP 3072 + ECDSA P-256, envuelve privadas y las sube. */
export async function createKeys(phrase: string): Promise<Keys> {
  const encPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const sigPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const encSpki = await exportSpki(encPair.publicKey);
  const sigSpki = await exportSpki(sigPair.publicKey);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKek(phrase, salt);
  const privs = enc.encode(
    JSON.stringify({
      enc: await exportPkcs8(encPair.privateKey),
      sig: await exportPkcs8(sigPair.privateKey),
    }),
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: WRAP_AD }, kek, privs);

  await api("PUT", "/keys/me", {
    enc_public_key: encSpki,
    sig_public_key: sigSpki,
    wrapped_private_keys: JSON.stringify({ iv: toB64(iv), ct: toB64(ct) }),
    kdf_salt: toB64(salt),
    kdf_params: JSON.stringify(ARGON2),
  });

  return {
    encPrivate: encPair.privateKey,
    encPublic: encPair.publicKey,
    sigPrivate: sigPair.privateKey,
    sigPublic: sigPair.publicKey,
    encSpki,
    sigSpki,
  };
}

/** Sesiones siguientes: descarga el respaldo envuelto y lo abre con la frase. */
export async function unlockKeys(phrase: string): Promise<Keys> {
  const stored = await api<{
    enc_public_key: string;
    sig_public_key: string;
    wrapped_private_keys: string;
    kdf_salt: string;
    kdf_params: string;
  }>("GET", "/keys/me");

  const params = JSON.parse(stored.kdf_params) as { alg: string; m?: number; t?: number; p?: number };
  if (params.alg !== "argon2id") {
    throw new Error(`KDF no soportado en este cliente: ${params.alg}`);
  }

  const salt = fromB64(stored.kdf_salt);
  const kek = await deriveKek(phrase, salt);
  const wrapped = JSON.parse(stored.wrapped_private_keys) as { iv: string; ct: string };
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(wrapped.iv), additionalData: WRAP_AD },
    kek,
    fromB64(wrapped.ct),
  );
  const { enc: encPkcs8, sig: sigPkcs8 } = JSON.parse(new TextDecoder().decode(plain)) as {
    enc: string;
    sig: string;
  };

  const encPrivate = await crypto.subtle.importKey(
    "pkcs8",
    fromB64(encPkcs8),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
  const encPublic = await crypto.subtle.importKey(
    "spki",
    fromB64(stored.enc_public_key),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
  const sigPrivate = await crypto.subtle.importKey(
    "pkcs8",
    fromB64(sigPkcs8),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const sigPublic = await crypto.subtle.importKey(
    "spki",
    fromB64(stored.sig_public_key),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  return {
    encPrivate,
    encPublic,
    sigPrivate,
    sigPublic,
    encSpki: stored.enc_public_key,
    sigSpki: stored.sig_public_key,
  };
}
