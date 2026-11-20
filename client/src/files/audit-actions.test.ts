import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import { buildAuditEntry, logAudit } from "../audit/api";
import { verifyAndDecrypt, encryptFile, wrapDek } from "../crypto/envelope";
import { toB64 } from "../crypto/encoding";
import type { Keys } from "../crypto/keys";
import { makeTestKeys } from "../test-utils/files";
import { deleteFile, fetchFilePackage } from "./api";
import { onDownload } from "./download";
import { shareFile } from "./share";
import { uploadFile } from "./upload";
import { signedManifest } from "./manifest";

vi.mock("../api", () => ({ api: vi.fn() }));
vi.mock("../audit/api", () => ({
  buildAuditEntry: vi.fn(),
  logAudit: vi.fn(),
}));
vi.mock("../crypto/envelope", () => ({
  encryptFile: vi.fn(),
  wrapDek: vi.fn(),
  verifyAndDecrypt: vi.fn(),
}));
vi.mock("./manifest", () => ({ signedManifest: vi.fn() }));
vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return { ...actual, fetchFilePackage: vi.fn() };
});
const mockedApi = vi.mocked(api);
const mockedBuildAuditEntry = vi.mocked(buildAuditEntry);
const mockedLogAudit = vi.mocked(logAudit);
const mockedEncryptFile = vi.mocked(encryptFile);
const mockedWrapDek = vi.mocked(wrapDek);
const mockedVerifyAndDecrypt = vi.mocked(verifyAndDecrypt);
const mockedFetchFilePackage = vi.mocked(fetchFilePackage);
const mockedSignedManifest = vi.mocked(signedManifest);
const fileId = "f5134ae8-70c8-4081-a4c1-8c3cdbf0e345";
const audit = {
  event: '{"action":"upload"}',
  prev_hash: "0".repeat(64),
  entry_hash: "1".repeat(64),
  signature: "signature",
};

let keys: Keys;

describe("file operation audit integration", () => {
  beforeAll(async () => {
    keys = await makeTestKeys();
  });

  beforeEach(() => {
    vi.resetAllMocks();
    mockedApi.mockImplementation(async <T>(method: string, path: string): Promise<T> => {
      if (method === "POST" && path === "/files/new-id") {
        return { id: fileId } as T;
      }
      return { ok: true } as T;
    });
    mockedBuildAuditEntry.mockResolvedValue(audit);
    mockedEncryptFile.mockResolvedValue({
      blob: new Uint8Array([1, 2, 3]),
      rawDek: new Uint8Array([4, 5, 6]),
    });
    mockedSignedManifest.mockResolvedValue({
      manifest: '{"id":"file","version":1}',
      manifest_signature: "manifest-signature",
    });
    mockedWrapDek.mockResolvedValue("wrapped-dek");
    mockedFetchFilePackage.mockResolvedValue({
      meta: {
        id: fileId,
        owner: "alice",
        version: 1,
        manifest: "{}",
        manifest_signature: "signature",
        wrapped_dek: "wrapped-dek",
      },
      blob: new Uint8Array(),
    });
    mockedVerifyAndDecrypt.mockResolvedValue({
      plain: new Uint8Array([1, 2, 3]),
      m: { id: fileId, version: 2, name: "report.txt", size: 3, sha256: "hash" },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("includes a signed upload event in the multipart request", async () => {
    const file = new File(["content"], "report.txt");

    await uploadFile(keys, "alice", file);

    expect(mockedBuildAuditEntry).toHaveBeenCalledWith(keys, {
      action: "upload",
      actor: "alice",
      file: fileId,
      version: 1,
    });
    const request = mockedApi.mock.calls.find(([, path]) => path === "/files");
    expect(request?.[2]).toBeInstanceOf(FormData);
    const form = request?.[2] as FormData;
    expect(JSON.parse(form.get("audit") as string)).toEqual(audit);
  });

  it("sends a signed delete event as the request body", async () => {
    await deleteFile(keys, "alice", fileId);

    expect(mockedBuildAuditEntry).toHaveBeenCalledWith(keys, {
      action: "delete",
      actor: "alice",
      file: fileId,
    });
    expect(mockedApi).toHaveBeenCalledWith("DELETE", `/files/${fileId}`, audit);
  });

  it("wraps the file key for the recipient and includes a signed share event", async () => {
    const targetPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    const targetSigPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const rawDek = new Uint8Array([7, 8, 9]);
    const wrappedForOwner = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      keys.encPublic,
      rawDek,
    );
    mockedFetchFilePackage.mockResolvedValue({
      meta: {
        id: fileId,
        owner: "alice",
        version: 1,
        manifest: "{}",
        manifest_signature: "signature",
        wrapped_dek: toB64(wrappedForOwner),
      },
      blob: new Uint8Array(),
    });
    const targetPublicKey = toB64(await crypto.subtle.exportKey("spki", targetPair.publicKey));
    const targetSigPublicKey = toB64(await crypto.subtle.exportKey("spki", targetSigPair.publicKey));
    mockedApi.mockImplementation(async <T>(method: string, path: string): Promise<T> => {
      if (method === "GET" && path === "/keys/bob") {
        return { enc_public_key: targetPublicKey, sig_public_key: targetSigPublicKey } as T;
      }
      return { ok: true } as T;
    });
    vi.stubGlobal("localStorage", {
      getItem: () => null,
      setItem: vi.fn(),
    });
    vi.stubGlobal("window", { confirm: vi.fn(() => true) });

    await shareFile(keys, "alice", fileId, "bob");

    expect(mockedBuildAuditEntry).toHaveBeenCalledWith(keys, {
      action: "share",
      actor: "alice",
      file: fileId,
      to: "bob",
    });
    const request = mockedApi.mock.calls.find(([, path]) => path === `/files/${fileId}/share`);
    const body = request?.[2] as { username: string; wrapped_dek: string; audit: unknown };
    expect(body.username).toBe("bob");
    expect(body.audit).toEqual(audit);
    expect(body.wrapped_dek).toBe("wrapped-dek");
  });

  it("logs a successful download before triggering the browser download", async () => {
    const anchor = { href: "", download: "", click: vi.fn() };
    const createObjectURL = vi.fn(() => "blob:download");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("document", { createElement: vi.fn(() => anchor) });
    vi.stubGlobal("URL", { createObjectURL, revokeObjectURL });

    await onDownload(keys, "alice", fileId);

    expect(mockedLogAudit).toHaveBeenCalledWith(keys, {
      action: "download",
      actor: "alice",
      file: fileId,
      version: 2,
    });
    expect(anchor.download).toBe("report.txt");
    expect(anchor.click).toHaveBeenCalledOnce();
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:download");
  });
});
