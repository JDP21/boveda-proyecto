import { api } from "../api";
import type { FilePackage } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { buildAuditEntry } from "../auth/api";

export type FileItem = {
  id: string;
  owner: string;
  is_owner: boolean;
  version: number;
  size: number;
  manifest: string;
  manifest_signature: string;
  updated_at: string;
};

export const listFiles = () => api<FileItem[]>("GET", "/files");

export async function fetchFilePackage(id: string): Promise<FilePackage> {
  const meta = await api<FilePackage["meta"]>("GET", `/files/${id}/meta`);
  const blob = new Uint8Array(await api<ArrayBuffer>("GET", `/files/${id}/blob`));
  return { meta, blob };
}

export async function deleteFile(keys: Keys, username: string, id: string) {
  const audit = await buildAuditEntry(keys, {
    action: "delete",
    actor: username,
    file: id,
  });
  return api("DELETE", `/files/${id}`, audit);
}
