import { useState, type FormEvent } from "react";
import { createKeys, unlockKeys, type Keys } from "../crypto/keys";

type Props = {
  hasKeys: boolean;
  onReady: (keys: Keys) => void;
};

export function UnlockKeys({ hasKeys, onReady }: Props) {
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (phrase.length < 12) {
        throw new Error("Usa una frase de recuperación de al menos 12 caracteres");
      }
      const keys = hasKeys ? await unlockKeys(phrase) : await createKeys(phrase);
      onReady(keys);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="panel" onSubmit={submit}>
      <h2>{hasKeys ? "Desbloquear claves" : "Generar claves"}</h2>
      <p className="muted">
        {hasKeys
          ? "Introduce la misma frase de recuperación para desenvolver tus claves privadas."
          : "Se crearán RSA-OAEP 3072 y ECDSA P-256. La frase nunca sale del navegador (Argon2id → AES-GCM)."}
      </p>
      <label>
        Frase de recuperación
        <input
          type="password"
          autoComplete="off"
          value={phrase}
          onChange={(e) => setPhrase(e.target.value)}
          disabled={busy}
        />
      </label>
      <button type="submit" disabled={busy}>
        {busy ? (hasKeys ? "Desbloqueando…" : "Generando (puede tardar)…") : hasKeys ? "Desbloquear" : "Crear y subir"}
      </button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}
