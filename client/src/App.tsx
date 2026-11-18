import { useCallback, useEffect, useState } from "react";
import { getToken } from "./api";
import { logout, me } from "./auth/passkeys";
import { AuthForm } from "./components/AuthForm";
import { FileTable } from "./components/FileTable";
import { UnlockKeys } from "./components/UnlockKeys";
import type { Keys } from "./crypto/keys";
import { fingerprint } from "./crypto/sign";

type Session = { username: string; has_keys: boolean };

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [keys, setKeys] = useState<Keys | null>(null);
  const [fp, setFp] = useState("");
  const [bootError, setBootError] = useState("");
  const [loading, setLoading] = useState(true);

  const refreshSession = useCallback(async () => {
    if (!getToken()) {
      setSession(null);
      setKeys(null);
      setLoading(false);
      return;
    }
    try {
      const info = await me();
      setSession({ username: info.username, has_keys: info.has_keys });
      if (!info.has_keys) setKeys(null);
    } catch (e) {
      setBootError(e instanceof Error ? e.message : String(e));
      setSession(null);
      setKeys(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const onKeysReady = async (k: Keys) => {
    setKeys(k);
    setFp(await fingerprint(k.encSpki, k.sigSpki));
    setSession((s) => (s ? { ...s, has_keys: true } : s));
  };

  const onLogout = async () => {
    await logout();
    setKeys(null);
    setSession(null);
    setFp("");
  };

  if (loading) {
    return (
      <main className="app">
        <p className="muted">Cargando…</p>
      </main>
    );
  }

  if (!session) {
    return (
      <main className="app">
        {bootError && <p role="alert">{bootError}</p>}
        <AuthForm onDone={() => void refreshSession()} />
      </main>
    );
  }

  if (!keys) {
    return (
      <main className="app">
        <header className="top">
          <strong>{session.username}</strong>
          <button type="button" className="ghost" onClick={() => void onLogout()}>
            Salir
          </button>
        </header>
        <UnlockKeys hasKeys={session.has_keys} onReady={(k) => void onKeysReady(k)} />
      </main>
    );
  }

  return (
    <main className="app">
      <header className="top">
        <div>
          <strong>{session.username}</strong>
          <p className="fp" title="Compártela por un canal externo al recibir archivos">
            Tu huella: {fp || "…"}
          </p>
        </div>
        <button type="button" className="ghost" onClick={() => void onLogout()}>
          Salir
        </button>
      </header>
      <FileTable keys={keys} username={session.username} />
    </main>
  );
}
