// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchAuditLog, verifyFullAuditChain, type AuditRecord } from "../audit/api";
import { AuditLog } from "./AuditLog";

vi.mock("../audit/api", () => ({
  fetchAuditLog: vi.fn(),
  verifyFullAuditChain: vi.fn(),
}));

const mockedFetchAuditLog = vi.mocked(fetchAuditLog);
const mockedVerifyChain = vi.mocked(verifyFullAuditChain);

const record: AuditRecord = {
  seq: 1,
  actor: "alice",
  event: JSON.stringify({ action: "upload", file: "12345678-file" }),
  prev_hash: "0".repeat(64),
  entry_hash: "a".repeat(64),
  signature: "signature",
  signer_key: "public-key",
  created_at: "2026-01-01T00:00:00",
};

describe("AuditLog", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows a verified audit chain and its entries", async () => {
    mockedFetchAuditLog.mockResolvedValue([record]);
    mockedVerifyChain.mockResolvedValue({ ok: true, count: 1 });

    render(<AuditLog />);

    expect((await screen.findByRole("status")).textContent).toContain("1 entrada verificada");
    expect(screen.getByText("alice")).toBeTruthy();
    expect(screen.getByText("upload")).toBeTruthy();
  });

  it("shows an integrity alert when verification fails", async () => {
    mockedFetchAuditLog.mockResolvedValue([record]);
    mockedVerifyChain.mockResolvedValue({
      ok: false,
      brokenAt: 1,
      reason: "signature",
    });

    render(<AuditLog />);

    expect((await screen.findByRole("alert")).textContent).toContain(
      "ALERTA DE MANIPULACIÓN",
    );
    expect(screen.getByText("signature")).toBeTruthy();
  });

  it("shows API errors and lets the user retry verification", async () => {
    mockedFetchAuditLog
      .mockRejectedValueOnce(new Error("503: API no disponible"))
      .mockResolvedValueOnce([record]);
    mockedVerifyChain.mockResolvedValue({ ok: true, count: 1 });

    render(<AuditLog />);

    expect(await screen.findByText("503: API no disponible")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Re-verificar cadena" }));

    await waitFor(() => {
      expect(mockedFetchAuditLog).toHaveBeenCalledTimes(2);
      expect(screen.getByRole("status").textContent).toContain("1 entrada verificada");
    });
  });

  it("shows an empty-log message when no records exist", async () => {
    mockedFetchAuditLog.mockResolvedValue([]);
    mockedVerifyChain.mockResolvedValue({ ok: true, count: 0 });

    render(<AuditLog />);

    expect(await screen.findByText("No hay eventos registrados todavía.")).toBeTruthy();
  });
});
