import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { api, setToken } from "../api";

export async function register(username: string) {
  const optionsJSON = await api<PublicKeyCredentialCreationOptionsJSON>(
    "POST",
    "/auth/register/options",
    { username },
  );
  const credential = await startRegistration({ optionsJSON });
  const { token } = await api<{ token: string }>("POST", "/auth/register/verify", {
    username,
    credential,
  });
  setToken(token);
}

export async function login(username: string) {
  const optionsJSON = await api<PublicKeyCredentialRequestOptionsJSON>(
    "POST",
    "/auth/login/options",
    { username },
  );
  const credential = await startAuthentication({ optionsJSON });
  const { token } = await api<{ token: string }>("POST", "/auth/login/verify", {
    username,
    credential,
  });
  setToken(token);
}

export const me = () =>
  api<{ username: string; has_keys: boolean; created_at?: string }>("GET", "/auth/me");

export async function logout() {
  try {
    await api("POST", "/auth/logout");
  } finally {
    setToken(null);
  }
}

type PublicKeyCredentialCreationOptionsJSON = Parameters<
  typeof startRegistration
>[0]["optionsJSON"];
type PublicKeyCredentialRequestOptionsJSON = Parameters<
  typeof startAuthentication
>[0]["optionsJSON"];
