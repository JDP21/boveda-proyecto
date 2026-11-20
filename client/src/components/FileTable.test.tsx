// @vitest-environment jsdom
// Runtime validation coverage for: file integrity status controls
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Keys } from "../crypto/keys";
import { FileTable } from "./FileTable";

vi.mock("../crypto/envelope", () => ({
  getSeenVersion: vi.fn(() => 0),
  verifyManifestSignature: vi.fn(async (_key: string, _manifest: string, signature: string) =>
    signature === "valid-signature"
  ),
}));
vi.mock("../files/api", () => ({
  deleteFile: vi.fn(),
  listFiles: vi.fn(),
}));
vi.mock("../files/download", () => ({ onDownload: vi.fn() }));
vi.mock("../files/share", () => ({
  listFileAccess: vi.fn(),
  revokeAccess: vi.fn(),
  shareFile: vi.fn(),
  trustedKeys: vi.fn(),
}));
vi.mock("../files/upload", () => ({ uploadFile: vi.fn() }));

import { listFiles } from "../files/api";

const mockedListFiles = vi.mocked(listFiles);
const keys = {} as Keys;

function row(id: string, signature: string) {
  return {
    id,
    owner: "alice",
    is_owner: true,
    version: 1,
    size: 12,
    manifest: JSON.stringify({ id, version: 1, name: `${id}.txt`, size: 12 }),
    manifest_signature: signature,
  };
}

describe("FileTable integrity controls", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => cleanup());

  it("blocks download, sharing, and access management for an invalid manifest", async () => {
    mockedListFiles.mockResolvedValue([row("tampered", "bad-signature")]);

    render(<FileTable keys={keys} username="alice" />);

    expect(await screen.findByText(/Firma ECDSA inválida/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Descargar" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByRole("button", { name: "Compartir" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByRole("button", { name: "Gestionar accesos" }).hasAttribute("disabled")).toBe(true);
  });

  it("allows file operations when the signed manifest is valid", async () => {
    mockedListFiles.mockResolvedValue([row("valid", "valid-signature")]);

    render(<FileTable keys={keys} username="alice" />);

    expect(await screen.findByText("✔ Firma válida")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Descargar" }).hasAttribute("disabled")).toBe(false);
    expect(screen.getByRole("button", { name: "Compartir" }).hasAttribute("disabled")).toBe(false);
    expect(screen.getByRole("button", { name: "Gestionar accesos" }).hasAttribute("disabled")).toBe(false);
  });
});
