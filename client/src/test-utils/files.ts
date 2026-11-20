import { toB64 } from "../crypto/encoding";
import { encryptFile, wrapDek, type FilePackage } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { signedManifest } from "../files/manifest";

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

export async function makeTestPackage(
  keys: Keys,
  fileId: string,
  version: number,
  plain: Uint8Array,
  owner = "alice",
): Promise<FilePackage> {
  const { blob, rawDek } = await encryptFile(fileId, version, plain);
  const { manifest, manifest_signature } = await signedManifest(
    keys,
    fileId,
    version,
    "test.txt",
    plain.byteLength,
    blob,
  );

  return {
    meta: {
      id: fileId,
      owner,
      version,
      manifest,
      manifest_signature,
      wrapped_dek: await wrapDek(rawDek, keys.encPublic),
    },
    blob,
  };
}
