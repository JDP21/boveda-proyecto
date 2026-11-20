import { type FormEvent, useCallback, useEffect, useState } from "react";
import type { Keys } from "../crypto/keys";
import { deleteFile, listFiles } from "../files/api";
import { onDownload } from "../files/download";
import { listFileAccess, revokeAccess, shareFile } from "../files/share";
import { uploadFile } from "../files/upload";

type FileRow = {
  id: string;
  owner: string;
  is_owner: boolean;
  version: number;
  size: number;
  manifest: string;
  manifest_signature: string;
};

function extractName(manifestJson: string, fallbackId: string): string {
  try {
    const parsed = JSON.parse(manifestJson) as { name?: string };
    return parsed.name || `${fallbackId.slice(0, 8)}…`;
  } catch {
    return `${fallbackId.slice(0, 8)}…`;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function FileTable({ keys, username }: { keys: Keys; username: string }) {
  const [files, setFiles] = useState<FileRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [error, setError] = useState("");

  // Estado del panel "Gestionar accesos"
  const [managingFile, setManagingFile] = useState<FileRow | null>(null);
  const [accessUsers, setAccessUsers] = useState<string[]>([]);
  const [loadingAccess, setLoadingAccess] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listFiles();
      setFiles(data as FileRow[]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

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

  const handleDownload = async (f: FileRow) => {
    setBusy(true);
    setError("");
    setStatusMsg("Verificando firma, hash y descifrando…");
    try {
      await onDownload(keys, username, f.id);
      setStatusMsg(`Descarga verificada: ${extractName(f.manifest, f.id)}`);
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleShare = async (f: FileRow) => {
    const to = window.prompt(`Usuario con quien compartir "${extractName(f.manifest, f.id)}":`);
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

  const openManageAccess = async (f: FileRow) => {
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

  const handleDelete = async (f: FileRow) => {
    const name = extractName(f.manifest, f.id);
    if (!window.confirm(`¿Eliminar permanentemente "${name}"?`)) return;

    setBusy(true);
    setError("");
    setStatusMsg("Eliminando archivo y registrando auditoría…");
    try {
      await deleteFile(keys, username, f.id);
      if (managingFile?.id === f.id) setManagingFile(null);
      setStatusMsg(`Archivo "${name}" eliminado.`);
      await refresh();
    } catch (err) {
      setStatusMsg("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <form onSubmit={(e) => void handleUpload(e)} style={{ display: "flex", gap: "0.75rem", marginBottom: "1.25rem" }}>
        <input type="file" name="file" required disabled={busy} />
        <button type="submit" disabled={busy}>
          Subir cifrado
        </button>
      </form>

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
              Accesos de: {extractName(managingFile.manifest, managingFile.id)} (v{managingFile.version})
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
        <p className="muted">Cargando archivos…</p>
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
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td title={f.id}>{extractName(f.manifest, f.id)}</td>
                <td>{f.owner}</td>
                <td>v{f.version}</td>
                <td>{formatBytes(f.size)}</td>
                <td style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                  <button type="button" className="ghost" disabled={busy} onClick={() => void handleDownload(f)}>
                    Descargar
                  </button>
                  {f.is_owner && (
                    <>
                      <button type="button" className="ghost" disabled={busy} onClick={() => void handleShare(f)}>
                        Compartir
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        disabled={busy}
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