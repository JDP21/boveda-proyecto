// Runtime validation coverage for: authenticated file API requests
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, getToken } from "../api";
import { buildAuditEntry } from "../audit/api";
import { deleteFile, fetchFilePackage, listFiles } from "./api";

vi.mock("../api", () => ({
  api: vi.fn(),
  getToken: vi.fn(),
}));
vi.mock("../audit/api", () => ({
  buildAuditEntry: vi.fn(),
}));

const mockedApi = vi.mocked(api);
const mockedGetToken = vi.mocked(getToken);
const mockedBuildAuditEntry = vi.mocked(buildAuditEntry);
const audit = {
  event: '{"action":"delete"}',
  prev_hash: "0".repeat(64),
  entry_hash: "a".repeat(64),
  signature: "signature",
};

describe("file API", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockedBuildAuditEntry.mockResolvedValue(audit);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("lists files through the authenticated API client", async () => {
    const files = [{ id: "file-1" }];
    mockedApi.mockResolvedValue(files);

    await expect(listFiles()).resolves.toBe(files);
    expect(mockedApi).toHaveBeenCalledWith("GET", "/files");
  });

  it("fetches metadata and the encrypted blob with the current bearer token", async () => {
    const meta = {
      id: "file-1",
      owner: "alice",
      version: 1,
      manifest: "{}",
      manifest_signature: "signature",
      wrapped_dek: "wrapped",
    };
    const bytes = new Uint8Array([1, 2, 3]);
    mockedApi.mockResolvedValue(meta);
    mockedGetToken.mockReturnValue("session-token");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => bytes.buffer,
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await fetchFilePackage("file-1");

    expect(result.meta).toEqual(meta);
    expect([...result.blob]).toEqual([...bytes]);
    expect(fetchMock).toHaveBeenCalledWith("/api/files/file-1/blob", {
      headers: { Authorization: "Bearer session-token" },
    });
  });

  it("surfaces blob download failures instead of returning a partial package", async () => {
    mockedApi.mockResolvedValue({
      id: "file-1",
      owner: "alice",
      version: 1,
      manifest: "{}",
      manifest_signature: "signature",
      wrapped_dek: "wrapped",
    });
    mockedGetToken.mockReturnValue(null);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      text: async () => "Archivo no encontrado",
    }));

    await expect(fetchFilePackage("file-1")).rejects.toThrow("404: Archivo no encontrado");
  });

  it("signs a delete audit event and sends it with the delete request", async () => {
    const keys = {} as Parameters<typeof deleteFile>[0];
    mockedApi.mockResolvedValue({ ok: true });

    await deleteFile(keys, "alice", "file-1");

    expect(mockedBuildAuditEntry).toHaveBeenCalledWith(keys, {
      action: "delete",
      actor: "alice",
      file: "file-1",
    });
    expect(mockedApi).toHaveBeenCalledWith("DELETE", "/files/file-1", audit);
  });
});
