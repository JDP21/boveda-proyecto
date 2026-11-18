import { useCallback, useEffect, useState } from "react";
import type { Keys } from "../crypto/keys";
import { deleteFile, listFiles, type FileItem } from "../files/api";
import { onDownload } from "../files/download";
import { shareFile } from "../files/share";
import { uploadFile } from "../files/upload";

type Props = {
  keys: Keys;
  username: string;
};

export function FileTable({ keys, username }: Props) {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [shareFor, setShareFor] = useState<string | null>(null);
  const [shareTo, setShareTo] = useState("");

  const load = useCallback(() => {
    listFiles()
      .then(setFiles)
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const onUpload = async (fileList: FileList | null) => {
    const file = fileList?.[0];
    if (!file) return;
    setError("");
    setBusy(true);
    try {
      await uploadFile(keys, username, file);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async (id: string) => {
    setError("");
    setBusy(true);
    try {
      await onDownload(keys, username, id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("¿Eliminar este archivo de la bóveda?")) return;
    setError("");
    try {
      await deleteFile(keys, username, id);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleShare = async () => {
    if (!shareFor || !shareTo.trim()) return;
    setError("");
    setBusy(true);
    try {
      await shareFile(keys, username, shareFor, shareTo.trim().toLowerCase());
      setShareFor(null);
      setShareTo("");
      alert("Archivo compartido.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel wide">
      <div className="row between">
        <h2>Archivos</h2>
        <label className="file-btn">
          {busy ? "Trabajando…" : "Subir archivo"}
          <input
            type="file"
            hidden
            disabled={busy}
            onChange={(e) => {
              void onUpload(e.target.files);
              e.target.value = "";
            }}
          />
        </label>
      </div>

      {error && <p role="alert">{error}</p>}

      <table>
        <thead>
          <tr>
            <th>Nombre</th>
            <th>Versión</th>
            <th>Tamaño</th>
            <th>Propietario</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {files.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No hay archivos aún.
              </td>
            </tr>
          )}
          {files.map((f) => {
            let name = f.id;
            let size = f.size;
            try {
              const m = JSON.parse(f.manifest) as { name?: string; size?: number };
              if (m.name) name = m.name;
              if (typeof m.size === "number") size = m.size;
            } catch {
              /* manifiesto ilegible: mostramos id */
            }
            return (
              <tr key={f.id}>
                <td>{name}</td>
                <td>{f.version}</td>
                <td>{size} B</td>
                <td>{f.owner}</td>
                <td className="actions">
                  <button type="button" disabled={busy} onClick={() => void handleDownload(f.id)}>
                    Descargar
                  </button>
                  {f.is_owner && (
                    <>
                      <button type="button" disabled={busy} onClick={() => setShareFor(f.id)}>
                        Compartir
                      </button>
                      <button type="button" className="danger" onClick={() => void handleDelete(f.id)}>
                        Eliminar
                      </button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {shareFor && (
        <div className="share-box">
          <h3>Compartir archivo</h3>
          <p className="muted">Se pedirá confirmar la huella del destinatario antes de envolver la DEK.</p>
          <label>
            Usuario destinatario
            <input
              value={shareTo}
              onChange={(e) => setShareTo(e.target.value)}
              placeholder="bob"
              disabled={busy}
            />
          </label>
          <div className="row">
            <button type="button" disabled={busy} onClick={() => void handleShare()}>
              Confirmar y compartir
            </button>
            <button type="button" className="ghost" onClick={() => setShareFor(null)}>
              Cancelar
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
