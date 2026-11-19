import type { Keys } from "./crypto/keys";
import { toB64 } from "./crypto/encoding";

export async function makeTestKeys(): Promise<Keys> {
  const encPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const sigPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  return {
    encPrivate: encPair.privateKey,
    encPublic: encPair.publicKey,
    sigPrivate: sigPair.privateKey,
    sigPublic: sigPair.publicKey,
    encSpki: toB64(await crypto.subtle.exportKey("spki", encPair.publicKey)),
    sigSpki: toB64(await crypto.subtle.exportKey("spki", sigPair.publicKey)),
  };
}
