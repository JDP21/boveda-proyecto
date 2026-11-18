import { verifyAndDecrypt } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { fetchFilePackage } from "./api";
import { trustedKeys } from "./share";

/** TK-11.1: trae el paquete; la verificación/descifrado la hace verifyAndDecrypt. */
export async function onDownload(keys: Keys, username: string, id: string) {
  const pkg = await fetchFilePackage(id);
  const ownerSig =
    pkg.meta.owner === username
      ? keys.sigSpki
      : (await trustedKeys(pkg.meta.owner)).sig_public_key;
  const { plain, m } = await verifyAndDecrypt(keys, pkg, ownerSig);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([plain.buffer as ArrayBuffer]));
  a.download = m.name;
  a.click();
  URL.revokeObjectURL(a.href);
}
