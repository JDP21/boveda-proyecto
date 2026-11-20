import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import { logAudit } from "../audit/api";
import { createKeys } from "./keys";

vi.mock("hash-wasm", () => ({
  argon2id: vi.fn(async () => new Uint8Array(32)),
}));
vi.mock("../api", () => ({ api: vi.fn() }));
vi.mock("../audit/api", () => ({ logAudit: vi.fn() }));

const mockedApi = vi.mocked(api);
const mockedLogAudit = vi.mocked(logAudit);

describe("key creation audit integration", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockedApi.mockImplementation(async <T>(): Promise<T> => ({ ok: true } as T));
    mockedLogAudit.mockResolvedValue(undefined);
  });

  it("logs key generation after persisting keys and returns the generated keys", async () => {
    const keys = await createKeys("correct horse battery staple");

    expect(mockedApi).toHaveBeenCalledWith("PUT", "/keys/me", expect.objectContaining({
      enc_public_key: expect.any(String),
      sig_public_key: expect.any(String),
    }));
    expect(mockedLogAudit).toHaveBeenCalledWith(keys, { action: "keys" });
    expect(mockedApi.mock.invocationCallOrder[0]).toBeLessThan(
      mockedLogAudit.mock.invocationCallOrder[0],
    );
    expect(keys.encPrivate.algorithm.name).toBe("RSA-OAEP");
    expect(keys.sigPrivate.algorithm.name).toBe("ECDSA");
  });
});
