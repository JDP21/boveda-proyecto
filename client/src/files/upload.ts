import { api } from "../api";
import { buildAuditEntry } from "../audit/api";
import { encryptFile, wrapDek } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { signedManifest } from "./manifest";

export async function uploadFile(keys: Keys, username: string, file: File) {
  const { id } = await api<{ id: string }>("POST", "/files/new-id");
  const version = 1;
  const data = new Uint8Array(await file.arrayBuffer());

  const { blob, rawDek } = await encryptFile(id, version, data);
  const { manifest, manifest_signature } = await signedManifest(
    keys,
    id,
    version,
    file.name,
    data.byteLength,
    blob,
  );
  const wrapped_dek = await wrapDek(rawDek, keys.encPublic);
  const audit = await buildAuditEntry(keys, {
    action: "upload",
    actor: username,
    file: id,
    version,
  });

  const form = new FormData();
  form.append("file_id", id);
  form.append("version", String(version));
  form.append("wrapped_dek", wrapped_dek);
  form.append("manifest", manifest);
  form.append("manifest_signature", manifest_signature);
  form.append("audit", JSON.stringify(audit));
  form.append("blob", new Blob([blob.buffer as ArrayBuffer]), "blob.enc");
  return api("POST", "/files", form);
}