// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getToken } from "./api";
import { logout, me } from "./auth/passkeys";
import App from "./App";

vi.mock("./api", () => ({ getToken: vi.fn() }));
vi.mock("./auth/passkeys", () => ({
  logout: vi.fn(),
  me: vi.fn(),
}));
vi.mock("./crypto/sign", () => ({
  fingerprint: vi.fn(async () => "ABCD EFGH"),
}));
vi.mock("./components/AuthForm", () => ({
  AuthForm: ({ onDone }: { onDone: () => void }) => (
    <button type="button" onClick={onDone}>Volver a iniciar sesión</button>
  ),
}));
vi.mock("./components/UnlockKeys", () => ({
  UnlockKeys: ({ onReady }: { onReady: (keys: unknown) => void }) => (
    <button
      type="button"
      onClick={() => onReady({ encSpki: "enc", sigSpki: "sig" } as never)}
    >
      Simular desbloqueo
    </button>
  ),
}));
vi.mock("./components/FileTable", () => ({
  FileTable: () => <div>Vista de archivos</div>,
}));
vi.mock("./components/AuditLog", () => ({
  AuditLog: () => <div>Vista de auditoría</div>,
}));

const mockedGetToken = vi.mocked(getToken);
const mockedMe = vi.mocked(me);
const mockedLogout = vi.mocked(logout);

describe("App audit navigation", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockedGetToken.mockReturnValue("session-token");
    mockedMe.mockResolvedValue({ username: "alice", has_keys: true });
    mockedLogout.mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
  });

  async function unlock() {
    fireEvent.click(await screen.findByRole("button", { name: "Simular desbloqueo" }));
    await screen.findByText("Vista de archivos");
  }

  it("switches between files and the audit log", async () => {
    render(<App />);
    await unlock();

    fireEvent.click(screen.getByRole("button", { name: "Auditoría" }));
    expect(await screen.findByText("Vista de auditoría")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Archivos" }));
    expect(await screen.findByText("Vista de archivos")).toBeTruthy();
  });

  it("returns to the files tab after logout and a new session", async () => {
    render(<App />);
    await unlock();
    fireEvent.click(screen.getByRole("button", { name: "Auditoría" }));
    await screen.findByText("Vista de auditoría");

    fireEvent.click(screen.getByRole("button", { name: "Salir" }));
    fireEvent.click(await screen.findByRole("button", { name: "Volver a iniciar sesión" }));

    await waitFor(() => {
      expect(mockedMe).toHaveBeenCalledTimes(2);
    });
    await unlock();
    expect(screen.queryByText("Vista de auditoría")).toBeNull();
  });
});
