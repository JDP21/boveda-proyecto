import { type FormEvent, useCallback, useEffect, useState } from "react";
import { getSeenVersion, type ManifestData, verifyManifestSignature } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { deleteFile, listFiles } from "../files/api";
import { onDownload } from "../files/download";
import { listFileAccess, revokeAccess, shareFile, trustedKeys } from "../files/share";
import { uploadFile } from "../files/upload";

type RawFileRow = {
  id: string;
  owner: string;
  is_owner: boolean;
  version: number;
  size: number;
  manifest: string;
  manifest_signature: string;
};

type VerifiedFileRow = RawFileRow & {
  displayName: string;
  displaySize: number;
  integrityOk: boolean;
  integrityReason: string;
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function verifyRow(keys: Keys, currentUser: string, row: RawFileRow): Promise<VerifiedFileRow> {
  let parsed: Partial<ManifestData> = {};
  try {
    parsed = JSON.parse(row.manifest) as Partial<ManifestData>;
  } catch {
    return {
      ...row,
      displayName: `${row.id.slice(0, 8)}… (manifiesto corrupto)`,
      displaySize: row.size,
      integrityOk: false,
      integrityReason: "Manifiesto JSON inválido",
    };
  }

  const fallbackName = parsed.name || `${row.id.slice(0, 8)}…`;
  const displaySize = typeof parsed.size === "number" ? parsed.size : row.size;

  try {
    const ownerSigSpki = row.is_owner
      ? keys.sigSpki
      : (await trustedKeys(currentUser, row.owner)).sig_public_key;

    const sigValid = await verifyManifestSignature(ownerSigSpki, row.manifest, row.manifest_signature);
    if (!sigValid) {
      return {
        ...row,
        displayName: fallbackName,
        displaySize,
        integrityOk: false,
        integrityReason: "Firma ECDSA inválida (posible alteración del servidor)",
      };
    }

    if (parsed.id !== row.id || parsed.version !== row.version) {
      return {
        ...row,
        displayName: fallbackName,
        displaySize,
        integrityOk: false,
        integrityReason: "ID o versión del manifiesto no coincide con la fila",
      };
    }

    const lastSeen = getSeenVersion(currentUser, row.id);
    if (row.version < lastSeen) {
      return {
        ...row,
        displayName: fallbackName,
        displaySize,
        integrityOk: false,
        integrityReason: `Rollback detectado (v${row.version} < v${lastSeen} vista)`,
      };
    }

    return {
      ...row,
      displayName: fallbackName,
      displaySize,
      integrityOk: true,
      integrityReason: "Firma ECDSA verificada",
    };
  } catch (err) {
    return {
      ...row,
      displayName: fallbackName,
      displaySize,
      integrityOk: false,
      integrityReason: err instanceof Error ? err.message : "No se pudo verificar la clave del propietario",
    };
  }
}

export function FileTable({ keys, username }: { keys: Keys; username: string }) {
  const [files, setFiles] = useState<VerifiedFileRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [error, setError] = useState("");

  const [managingFile, setManagingFile] = useState<VerifiedFileRow | null>(null);
  const [accessUsers, setAccessUsers] = useState<string[]>([]);
  const [loadingAccess, setLoadingAccess] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const raw = (await listFiles()) as RawFileRow[];
      const verified: VerifiedFileRow[] = [];
      for (const item of raw) {
        verified.push(await verifyRow(keys, username, item));
      }
      setFiles(verified);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [keys, username]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleUpload = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem("file") as HTMLInputElement | null;
    const file = input?.files?.[0];
    if (!file) return;

    setBusy(true);
    setError("");
    setStatusMsg("Cifrando archivo en el navegador…");
    try {
      await uploadFile(keys, username, file);
      form.reset();
      setStatusMsg(`Archivo "${file.name}" cifrado y subido.`);
      await refresh();
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async (f: VerifiedFileRow) => {
    if (!f.integrityOk) {
      setError(`Descarga bloqueada para "${f.displayName}": ${f.integrityReason}`);
      return;
    }
    setBusy(true);
    setError("");
    setStatusMsg("Verificando firma, hash y descifrando…");
    try {
      await onDownload(keys, username, f.id);
      setStatusMsg(`Descarga verificada: ${f.displayName}`);
      await refresh();
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleShare = async (f: VerifiedFileRow) => {
    const to = window.prompt(`Usuario con quien compartir "${f.displayName}":`);
    if (!to) return;

    setBusy(true);
    setError("");
    setStatusMsg(`Compartiendo con ${to.trim()}…`);
    try {
      await shareFile(keys, username, f.id, to);
      setStatusMsg(`Archivo compartido con ${to.trim().toLowerCase()}.`);
      if (managingFile?.id === f.id) {
        setAccessUsers(await listFileAccess(f.id));
      }
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const openManageAccess = async (f: VerifiedFileRow) => {
    setManagingFile(f);
    setLoadingAccess(true);
    setError("");
    try {
      const users = await listFileAccess(f.id);
      setAccessUsers(users);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoadingAccess(false);
    }
  };

  const handleRevoke = async (targetUser: string) => {
    if (!managingFile) return;
    const confirmed = window.confirm(
      `¿Revocar el acceso de "${targetUser}"?\n\nSe generará una nueva clave DEK (v${managingFile.version + 1}) y el archivo se re-cifrará completamente.`,
    );
    if (!confirmed) return;

    setBusy(true);
    setError("");
    setStatusMsg(`Revocando a ${targetUser} y re-cifrando con nueva DEK…`);
    try {
      await revokeAccess(keys, username, managingFile.id, targetUser);
      const updatedUsers = await listFileAccess(managingFile.id);
      setAccessUsers(updatedUsers);
      setManagingFile((prev) => (prev ? { ...prev, version: prev.version + 1 } : null));
      setStatusMsg(`Acceso revocado para ${targetUser}. Archivo actualizado a v${managingFile.version + 1}.`);
      await refresh();
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (f: VerifiedFileRow) => {
    if (!window.confirm(`¿Eliminar permanentemente "${f.displayName}"?`)) return;

    setBusy(true);
    setError("");
    setStatusMsg("Eliminando archivo y registrando auditoría…");
    try {
      await deleteFile(keys, username, f.id);
      if (managingFile?.id === f.id) setManagingFile(null);
      setStatusMsg(`Archivo "${f.displayName}" eliminado.`);
      await refresh();
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const tamperedCount = files.filter((f) => !f.integrityOk).length;

  return (
    <section>
      <form onSubmit={(e) => void handleUpload(e)} style={{ display: "flex", gap: "0.75rem", marginBottom: "1.25rem" }}>
        <input type="file" name="file" required disabled={busy} />
        <button type="submit" disabled={busy}>
          Subir cifrado
        </button>
      </form>

      {tamperedCount > 0 && (
        <p role="alert" style={{ padding: "0.75rem", border: "1px solid #c62828", borderRadius: 6 }}>
          <strong>ALERTA DE INTEGRIDAD (HU-10):</strong> {tamperedCount}{" "}
          {tamperedCount === 1 ? "archivo tiene" : "archivos tienen"} firma o versión inválida. No confíes en sus metadatos.
        </p>
      )}

      {error && <p role="alert">{error}</p>}
      {statusMsg && !error && <p role="status" className="muted">{statusMsg}</p>}

      {managingFile && (
        <div
          style={{
            marginBottom: "1.25rem",
            padding: "1rem",
            border: "1px solid #3b4252",
            borderRadius: 8,
          }}
        >
          <div className="top" style={{ marginBottom: "0.75rem" }}>
            <strong>
              Accesos de: {managingFile.displayName} (v{managingFile.version})
            </strong>
            <button type="button" className="ghost" onClick={() => setManagingFile(null)} disabled={busy}>
              Cerrar
            </button>
          </div>

          {loadingAccess ? (
            <p className="muted">Cargando usuarios autorizados…</p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: "0.5rem" }}>
              {accessUsers.map((u) => (
                <li
                  key={u}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
                >
                  <span>
                    {u} {u === username && <span className="muted">(propietario)</span>}
                  </span>
                  {u !== username && (
                    <button
                      type="button"
                      className="ghost"
                      disabled={busy}
                      onClick={() => void handleRevoke(u)}
                    >
                      Revocar
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {loading ? (
        <p className="muted">Verificando firmas y cargando archivos…</p>
      ) : files.length === 0 ? (
        <p className="muted">No tienes archivos en la bóveda todavía.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Archivo</th>
              <th>Propietario</th>
              <th>Versión</th>
              <th>Tamaño</th>
              <th>Integridad</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id} style={!f.integrityOk ? { backgroundColor: "rgba(198, 40, 40, 0.15)" } : undefined}>
                <td title={f.id}>{f.displayName}</td>
                <td>{f.owner}</td>
                <td>v{f.version}</td>
                <td>{formatBytes(f.displaySize)}</td>
                <td title={f.integrityReason}>
                  {f.integrityOk ? (
                    <span style={{ color: "#66bb6a" }}>✔ Firma válida</span>
                  ) : (
                    <span style={{ color: "#ef5350", fontWeight: 600 }}>⚠ {f.integrityReason}</span>
                  )}
                </td>
                <td style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className="ghost"
                    disabled={busy || !f.integrityOk}
                    onClick={() => void handleDownload(f)}
                  >
                    Descargar
                  </button>
                  {f.is_owner && (
                    <>
                      <button
                        type="button"
                        className="ghost"
                        disabled={busy || !f.integrityOk}
                        onClick={() => void handleShare(f)}
                      >
                        Compartir
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        disabled={busy || !f.integrityOk}
                        onClick={() => void openManageAccess(f)}
                      >
                        Gestionar accesos
                      </button>
                      <button type="button" className="ghost" disabled={busy} onClick={() => void handleDelete(f)}>
                        Eliminar
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}