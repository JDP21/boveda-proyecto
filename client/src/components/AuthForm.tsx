import { useState, type FormEvent } from "react";
import { login, register } from "../auth/passkeys";

type Props = {
  onDone: () => void;
};

export function AuthForm({ onDone }: Props) {
  const [username, setUsername] = useState("");
  const [mode, setMode] = useState<"login" | "register">("register");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const name = username.trim().toLowerCase();
      if (!name) throw new Error("Escribe un nombre de usuario");
      if (mode === "register") await register(name);
      else await login(name);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="panel" onSubmit={submit}>
      <h1>Bóveda Zero-Knowledge</h1>
      <p className="muted">Autenticación exclusiva con passkeys (sin contraseña).</p>
      <label>
        Usuario
        <input
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="alice"
          disabled={busy}
        />
      </label>
      <div className="row">
        <button type="submit" disabled={busy}>
          {busy ? "Esperando passkey…" : mode === "register" ? "Registrarme" : "Iniciar sesión"}
        </button>
        <button
          type="button"
          className="ghost"
          disabled={busy}
          onClick={() => setMode(mode === "register" ? "login" : "register")}
        >
          {mode === "register" ? "Ya tengo cuenta" : "Crear cuenta"}
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
      <p className="hint">Abre siempre con <code>http://localhost:…</code>, no con 127.0.0.1.</p>
    </form>
  );
}
