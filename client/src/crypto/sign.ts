import { concat, enc, fromB64, sha256Hex, toB64 } from "./encoding";

export async function signText(priv: CryptoKey, text: string): Promise<string> {
  return toB64(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, enc.encode(text)),
  );
}

export async function verifyText(
  pubSpkiB64: string,
  text: string,
  sigB64: string,
): Promise<boolean> {
  const pub = await crypto.subtle.importKey(
    "spki",
    fromB64(pubSpkiB64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pub,
    fromB64(sigB64),
    enc.encode(text),
  );
}

/** Huella = SHA-256(SPKI cifrado ‖ SPKI firma), en grupos de 4. */
export async function fingerprint(encSpkiB64: string, sigSpkiB64: string): Promise<string> {
  const h = await sha256Hex(concat(fromB64(encSpkiB64), fromB64(sigSpkiB64)));
  return h
    .toUpperCase()
    .match(/.{4}/g)!
    .join(" ");
}
