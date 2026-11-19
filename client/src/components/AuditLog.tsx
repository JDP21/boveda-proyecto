import { useCallback, useEffect, useState } from "react";
import {
  type AuditRecord,
  type ChainVerificationResult,
  fetchAuditLog,
  verifyFullAuditChain,
} from "../auth/api";

function parseEvent(raw: string): Record<string, unknown> {
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { raw };
  }
}

export function AuditLog() {
  const [entries, setEntries] = useState<AuditRecord[]>([]);
  const [status, setStatus] = useState<ChainVerificationResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadAndVerify = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const log = await fetchAuditLog();
      const verification = await verifyFullAuditChain(log);
      setEntries(log);
      setStatus(verification);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAndVerify();
  }, [loadAndVerify]);

  return (
    <section>
      <div className="top" style={{ marginBottom: "1rem" }}>
        <h2>Bitácora de Auditoría (HU-07)</h2>
        <button type="button" className="ghost" onClick={() => void loadAndVerify()} disabled={loading}>
          {loading ? "Verificando…" : "Re-verificar cadena"}
        </button>
      </div>

      {error && <p role="alert">{error}</p>}

      {status && status.ok && (
        <p role="status" style={{ padding: "0.75rem", border: "1px solid #2e7d32", borderRadius: 6 }}>
          <strong>Cadena íntegra:</strong> {status.count}{" "}
          {status.count === 1 ? "entrada verificada" : "entradas verificadas"} (SHA-256 encadenado + firmas ECDSA P-256).
        </p>
      )}

      {status && !status.ok && (
        <p role="alert" style={{ padding: "0.75rem", border: "1px solid #c62828", borderRadius: 6 }}>
          <strong>ALERTA DE MANIPULACIÓN:</strong> Cadena o firma alterada en el bloque #{status.brokenAt} (fallo en{" "}
          <code>{status.reason}</code>).
        </p>
      )}

      {!loading && entries.length === 0 ? (
        <p className="muted">No hay eventos registrados todavía.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Fecha (UTC)</th>
              <th>Actor</th>
              <th>Acción</th>
              <th>Archivo</th>
              <th>Hash de entrada</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => {
              const ev = parseEvent(entry.event);
              return (
                <tr key={entry.seq}>
                  <td>{entry.seq}</td>
                  <td>{new Date(entry.created_at + "Z").toLocaleString()}</td>
                  <td>{entry.actor}</td>
                  <td>
                    <code>{String(ev.action ?? "—")}</code>
                    {ev.to ? ` → ${String(ev.to)}` : ""}
                    {ev.user ? ` ✕ ${String(ev.user)}` : ""}
                  </td>
                  <td title={String(ev.file ?? "")}>
                    {ev.file ? `${String(ev.file).slice(0, 8)}…` : "—"}
                  </td>
                  <td title={entry.entry_hash}>
                    <code>{entry.entry_hash.slice(0, 12)}…</code>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}