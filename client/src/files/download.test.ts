// Runtime validation coverage for: verified and audited downloads
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { logAudit } from "../audit/api";
import { verifyAndDecrypt } from "../crypto/envelope";
import { fetchFilePackage } from "./api";
import { onDownload } from "./download";
import { trustedKeys } from "./share";

vi.mock("../audit/api", () => ({ logAudit: vi.fn() }));
vi.mock("../crypto/envelope", () => ({ verifyAndDecrypt: vi.fn() }));
vi.mock("./api", () => ({ fetchFilePackage: vi.fn() }));
vi.mock("./share", () => ({ trustedKeys: vi.fn() }));

const mockedLogAudit = vi.mocked(logAudit);
const mockedVerifyAndDecrypt = vi.mocked(verifyAndDecrypt);
const mockedFetchFilePackage = vi.mocked(fetchFilePackage);
const mockedTrustedKeys = vi.mocked(trustedKeys);
const keys = { sigSpki: "owner-key" } as Parameters<typeof onDownload>[0];
const pkg = {
  meta: {
    id: "file-1",
    owner: "alice",
    version: 2,
    manifest: "{}",
    manifest_signature: "signature",
    wrapped_dek: "wrapped",
  },
  blob: new Uint8Array(),
};

describe("onDownload", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockedFetchFilePackage.mockResolvedValue(pkg);
    mockedVerifyAndDecrypt.mockResolvedValue({
      plain: new Uint8Array([1, 2, 3]),
      m: { id: "file-1", version: 2, name: "report.txt", size: 3, sha256: "hash" },
    });
    mockedLogAudit.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies and audits before triggering a download for an owned file", async () => {
    const anchor = { href: "", download: "", click: vi.fn() };
    const createObjectURL = vi.fn(() => "blob:download");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("document", { createElement: vi.fn(() => anchor) });
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL });

    await onDownload(keys, "alice", "file-1");

    expect(mockedVerifyAndDecrypt).toHaveBeenCalledWith(keys, pkg, "owner-key", "alice");
    expect(mockedLogAudit).toHaveBeenCalledWith(keys, {
      action: "download",
      actor: "alice",
      file: "file-1",
      version: 2,
    });
    expect(anchor.download).toBe("report.txt");
    expect(anchor.click).toHaveBeenCalledOnce();
    expect(mockedLogAudit.mock.invocationCallOrder[0]).toBeLessThan(
      createObjectURL.mock.invocationCallOrder[0],
    );
    expect(mockedTrustedKeys).not.toHaveBeenCalled();
  });

  it("uses the trusted owner's signing key for a shared file", async () => {
    const anchor = { href: "", download: "", click: vi.fn() };
    vi.stubGlobal("document", { createElement: vi.fn(() => anchor) });
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:download"), revokeObjectURL: vi.fn() });
    mockedFetchFilePackage.mockResolvedValue({
      ...pkg,
      meta: { ...pkg.meta, owner: "bob" },
    });
    mockedTrustedKeys.mockResolvedValue({
      username: "bob",
      enc_public_key: "enc-key",
      sig_public_key: "bob-signing-key",
      updated_at: "2026-01-01",
    });

    await onDownload(keys, "alice", "file-1");

    expect(mockedTrustedKeys).toHaveBeenCalledWith("alice", "bob");
    expect(mockedVerifyAndDecrypt).toHaveBeenCalledWith(
      keys,
      expect.objectContaining({ meta: expect.objectContaining({ owner: "bob" }) }),
      "bob-signing-key",
      "alice",
    );
  });

  it("does not audit or download a file that fails integrity verification", async () => {
    const createObjectURL = vi.fn();
    vi.stubGlobal("document", { createElement: vi.fn() });
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL: vi.fn() });
    mockedVerifyAndDecrypt.mockRejectedValue(new Error("Firma inválida"));

    await expect(onDownload(keys, "alice", "file-1")).rejects.toThrow("Firma inválida");

    expect(mockedLogAudit).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it("does not trigger a download when audit logging fails", async () => {
    const createObjectURL = vi.fn();
    vi.stubGlobal("document", { createElement: vi.fn() });
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL: vi.fn() });
    mockedLogAudit.mockRejectedValue(new Error("Audit API unavailable"));

    await expect(onDownload(keys, "alice", "file-1")).rejects.toThrow("Audit API unavailable");

    expect(createObjectURL).not.toHaveBeenCalled();
  });
});
