import type { Keys } from "../crypto/keys";
import { canonicalJSON, sha256Hex } from "../crypto/encoding";
import { signText } from "../crypto/sign";

/** TK-05.2: SHA-256 del blob completo (IV incluido) + firma ECDSA del manifiesto canónico. */
export async function signedManifest(
  keys: Keys,
  id: string,
  version: number,
  name: string,
  size: number,
  blob: Uint8Array,
) {
  const manifest = canonicalJSON({
    id,
    version,
    name,
    size,
    sha256: await sha256Hex(blob),
  });
  return { manifest, manifest_signature: await signText(keys.sigPrivate, manifest) };
}
