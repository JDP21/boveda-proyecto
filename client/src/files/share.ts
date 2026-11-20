import { api } from "../api";
import { buildAuditEntry } from "../auth/api";
import { fromB64 } from "../crypto/encoding";
import { encryptFile, verifyAndDecrypt, wrapDek } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { fingerprint } from "../crypto/sign";
import { fetchFilePackage } from "./api";
import { signedManifest } from "./manifest";

export type PublicKeyBundle = {
  username: string;
  enc_public_key: string;
  sig_public_key: string;
  updated_at: string;
};

const TRUSTED_STORAGE_KEY = "boveda_trusted_fps";

function loadTrusted(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(TRUSTED_STORAGE_KEY) ?? "{}") as Record<string, string>;
  } catch {
    return {};
  }
}

function saveTrusted(map: Record<string, string>): void {
  localStorage.setItem(TRUSTED_STORAGE_KEY, JSON.stringify(map));
}

/** Obtiene las claves públicas de otro usuario y exige verificación TOFU de su huella. */
export async function trustedKeys(username: string): Promise<PublicKeyBundle> {
  const target = username.trim().toLowerCase();
  const pk = await api<PublicKeyBundle>("GET", `/keys/${encodeURIComponent(target)}`);
  const fp = await fingerprint(pk.enc_public_key, pk.sig_public_key);
  const trusted = loadTrusted();

  if (trusted[target]) {
    if (trusted[target] !== fp) {
      throw new Error(
        `¡ALERTA! La huella de ${target} cambió respecto a la verificada anteriormente. Posible sustitución de clave.`,
      );
    }
    return pk;
  }

  const confirmed = window.confirm(
    `Huella de ${target}:\n\n${fp}\n\n¿Coincide con la que ${target} te mostró por un canal externo?`,
  );
  if (!confirmed) {
    throw new Error(`Verificación de huella cancelada para ${target}.`);
  }

  trusted[target] = fp;
  saveTrusted(trusted);
  return pk;
}

async function importRsaPublic(spkiB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    fromB64(spkiB64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

/** Lista los nombres de usuario que actualmente tienen acceso al archivo. */
export async function listFileAccess(fileId: string): Promise<string[]> {
  const res = await api<{ users: string[] }>("GET", `/files/${fileId}/access`);
  return res.users;
}

/** Comparte un archivo existente envolviendo su DEK actual con la clave pública del destinatario. */
export async function shareFile(keys: Keys, username: string, id: string, to: string) {
  const target = to.trim().toLowerCase();
  if (!target) throw new Error("Debes indicar un usuario destinatario.");
  if (target === username) throw new Error("No puedes compartir un archivo contigo mismo.");

  const pk = await trustedKeys(target);
  const { meta } = await fetchFilePackage(id);
  const rawDek = new Uint8Array(
    await crypto.subtle.decrypt({ name: "RSA-OAEP" }, keys.encPrivate, fromB64(meta.wrapped_dek)),
  );
  const toPub = await importRsaPublic(pk.enc_public_key);
  const wrapped_dek = await wrapDek(rawDek.buffer as ArrayBuffer, toPub);

  const audit = await buildAuditEntry(keys, {
    action: "share",
    actor: username,
    file: id,
    to: target,
  });

  return api("POST", `/files/${id}/share`, {
    username: target,
    wrapped_dek,
    audit,
  });
}

/**
 * Revoca el acceso de `userToRevoke` rotando la DEK:
 * descarga y descifra el archivo, genera una nueva DEK (versión + 1),
 * re-cifra el contenido y envuelve la nueva DEK únicamente para los usuarios autorizados restantes.
 */
export async function revokeAccess(
  keys: Keys,
  ownerUsername: string,
  fileId: string,
  userToRevoke: string,
) {
  const target = userToRevoke.trim().toLowerCase();
  if (target === ownerUsername) {
    throw new Error("No puedes revocar tu propio acceso como propietario.");
  }

  // 1. Consultar usuarios con acceso actual
  const users = await listFileAccess(fileId);

  // 2. Filtrar para conservar únicamente a los autorizados
  const remainingUsers = users.filter((u) => u !== target);
  if (remainingUsers.length === users.length) {
    throw new Error(`El usuario ${target} no tiene acceso a este archivo.`);
  }

  // 3. Descargar paquete actual y descifrarlo en memoria
  const pkg = await fetchFilePackage(fileId);
  const { plain, m } = await verifyAndDecrypt(keys, pkg, keys.sigSpki);

  // 4. Incrementar versión, generar nueva DEK, re-cifrar y firmar nuevo manifiesto
  const nextVersion = m.version + 1;
  const { blob, rawDek } = await encryptFile(fileId, nextVersion, plain);
  const { manifest, manifest_signature } = await signedManifest(
    keys,
    fileId,
    nextVersion,
    m.name,
    plain.byteLength,
    blob,
  );

  // 5. Envolver la nueva DEK solo para los usuarios restantes
  const wrappedDeks: Array<{ username: string; wrapped_dek: string }> = [];
  for (const u of remainingUsers) {
    if (u === ownerUsername) {
      wrappedDeks.push({
        username: u,
        wrapped_dek: await wrapDek(rawDek, keys.encPublic),
      });
    } else {
      const pk = await trustedKeys(u);
      const pub = await importRsaPublic(pk.enc_public_key);
      wrappedDeks.push({
        username: u,
        wrapped_dek: await wrapDek(rawDek, pub),
      });
    }
  }

  // 6. Construir FormData y entrada de auditoría encadenada
  const audit = await buildAuditEntry(keys, {
    action: "revoke",
    actor: ownerUsername,
    file: fileId,
    revoked: target,
    version: nextVersion,
  });

  const form = new FormData();
  form.append("version", String(nextVersion));
  form.append("manifest", manifest);
  form.append("manifest_signature", manifest_signature);
  form.append("wrapped_deks", JSON.stringify(wrappedDeks));
  form.append("audit", JSON.stringify(audit));
  form.append("blob", new Blob([blob.buffer as ArrayBuffer]), "blob.enc");

  // 7. Enviar actualización atómica al servidor
  return api("PUT", `/files/${fileId}`, form);
}