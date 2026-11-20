import { logAudit } from "../audit/api";
import { verifyAndDecrypt } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { fetchFilePackage } from "./api";
import { trustedKeys } from "./share";

export async function onDownload(keys: Keys, username: string, id: string) {
  const pkg = await fetchFilePackage(id);
  const ownerSig =
    pkg.meta.owner === username
      ? keys.sigSpki
      : (await trustedKeys(username, pkg.meta.owner)).sig_public_key;
  const { plain, m } = await verifyAndDecrypt(keys, pkg, ownerSig, username);
  await logAudit(keys, {
    action: "download",
    actor: username,
    file: id,
    version: m.version,
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([plain.buffer as ArrayBuffer]));
  a.download = m.name;
  a.click();
  URL.revokeObjectURL(a.href);
}