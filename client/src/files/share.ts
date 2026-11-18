import { api } from "../api";
import { fromB64, toB64 } from "../crypto/encoding";
import type { Keys } from "../crypto/keys";
import { fingerprint } from "../crypto/sign";
import { fetchFilePackage } from "./api";

type PublicKeys = {
  username?: string;
  enc_public_key: string;
  sig_public_key: string;
  updated_at?: string;
};

/** TK-06.1: verifica huella fuera de banda antes de usar claves ajenas. */
export async function trustedKeys(user: string): Promise<PublicKeys> {
  const pk = await api<PublicKeys>("GET", `/keys/${encodeURIComponent(user)}`);
  const fp = await fingerprint(pk.enc_public_key, pk.sig_public_key);
  const trusted = JSON.parse(localStorage.getItem("trusted") ?? "{}") as Record<string, string>;

  if (trusted[user] && trusted[user] !== fp) {
    throw new Error(
      `La huella de ${user} CAMBIÓ: posible sustitución de clave. Operación cancelada.`,
    );
  }
  if (!trusted[user]) {
    const ok = confirm(
      `Huella de ${user}:\n\n${fp}\n\n¿Coincide con la que ${user} te mostró por un canal externo?`,
    );
    if (!ok) throw new Error("Huella no verificada");
    trusted[user] = fp;
    localStorage.setItem("trusted", JSON.stringify(trusted));
  }
  return pk;
}

export async function shareFile(keys: Keys, _username: string, id: string, to: string) {
  const pk = await trustedKeys(to);
  const { meta } = await fetchFilePackage(id);
  const rawDek = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    keys.encPrivate,
    fromB64(meta.wrapped_dek),
  );
  const toPub = await crypto.subtle.importKey(
    "spki",
    fromB64(pk.enc_public_key),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  return api("POST", `/files/${id}/share`, {
    username: to,
    wrapped_dek: toB64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, toPub, rawDek)),
  });
}
