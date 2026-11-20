import { api, getToken } from "../api";
import { buildAuditEntry } from "../audit/api";
import type { FilePackage } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";

export async function listFiles() {
  return api("GET", "/files");
}

export async function fetchFilePackage(id: string): Promise<FilePackage> {
  const meta = await api<FilePackage["meta"]>("GET", `/files/${id}/meta`);

  const token = getToken();
  const res = await fetch(`/api/files/${id}/blob`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`${res.status}: ${await res.text()}`);
  }
  const blob = new Uint8Array(await res.arrayBuffer());
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