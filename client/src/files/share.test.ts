// Runtime validation coverage for: sharing and revoking encrypted file access
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import { buildAuditEntry } from "../audit/api";
import { fromB64, toB64 } from "../crypto/encoding";
import { verifyAndDecrypt, type FilePackage } from "../crypto/envelope";
import type { Keys } from "../crypto/keys";
import { makeTestKeys, makeTestPackage } from "../test-utils/files";
import { fetchFilePackage } from "./api";
import { revokeAccess, shareFile, trustedKeys } from "./share";

vi.mock("../api", () => ({ api: vi.fn() }));
vi.mock("../audit/api", () => ({ buildAuditEntry: vi.fn() }));
vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return { ...actual, fetchFilePackage: vi.fn() };
});

const mockedApi = vi.mocked(api);
const mockedBuildAuditEntry = vi.mocked(buildAuditEntry);
const mockedFetchFilePackage = vi.mocked(fetchFilePackage);
const fileId = "file-share-123";
const plain = new TextEncoder().encode("secret document");
const audit = {
  event: '{"action":"share"}',
  prev_hash: "0".repeat(64),
  entry_hash: "a".repeat(64),
  signature: "signature",
};

let ownerKeys: Keys;
let revokedKeys: Keys;
let remainingKeys: Keys;

function installBrowserStorage() {
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  });
  vi.stubGlobal("window", { confirm: vi.fn(() => true) });
  return values;
}

function installApiResponses(users: string[]) {
  mockedApi.mockImplementation(async <T>(method: string, path: string): Promise<T> => {
    if (method === "GET" && path.endsWith("/access")) {
      return { users } as T;
    }
    if (method === "GET" && path === "/keys/carol") {
      return {
        username: "carol",
        enc_public_key: remainingKeys.encSpki,
        sig_public_key: remainingKeys.sigSpki,
        updated_at: "2026-01-01T00:00:00",
      } as T;
    }
    return { ok: true } as T;
  });
}

describe("file sharing and access revocation", () => {
  beforeAll(async () => {
    [ownerKeys, revokedKeys, remainingKeys] = await Promise.all([
      makeTestKeys(),
      makeTestKeys(),
      makeTestKeys(),
    ]);
  });

  beforeEach(() => {
    installBrowserStorage();
    vi.resetAllMocks();
    mockedBuildAuditEntry.mockResolvedValue(audit);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("asks for first-time trust, wraps the DEK for the recipient, and submits the audit entry", async () => {
    installApiResponses([]);
    const pkg = await makeTestPackage(ownerKeys, fileId, 1, plain);
    mockedFetchFilePackage.mockResolvedValue(pkg);
    const recipientPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    const recipientSig = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const recipientSpki = toB64(await crypto.subtle.exportKey("spki", recipientPair.publicKey));
    const recipientSigSpki = toB64(await crypto.subtle.exportKey("spki", recipientSig.publicKey));
    mockedApi.mockImplementation(async <T>(method: string, path: string): Promise<T> => {
      if (method === "GET" && path === "/keys/bob") {
        return {
          username: "bob",
          enc_public_key: recipientSpki,
          sig_public_key: recipientSigSpki,
          updated_at: "2026-01-01T00:00:00",
        } as T;
      }
      return { ok: true } as T;
    });

    await shareFile(ownerKeys, "alice", fileId, " Bob ");

    const post = mockedApi.mock.calls.find(([method, path]) => method === "POST" && path.endsWith("/share"));
    expect(post).toBeDefined();
    const body = post?.[2] as { username: string; wrapped_dek: string; audit: unknown };
    expect(body.username).toBe("bob");
    expect(body.audit).toEqual(audit);
    expect(
      await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        recipientPair.privateKey,
        fromB64(body.wrapped_dek),
      ),
    ).toEqual(await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      ownerKeys.encPrivate,
      fromB64(pkg.meta.wrapped_dek),
    ));
    expect(JSON.parse(localStorage.getItem("trusted_alice") ?? "{}")).toHaveProperty("bob");
    expect(window.confirm).toHaveBeenCalledOnce();
  });

  it("does not share when the recipient fingerprint is not trusted", async () => {
    installApiResponses([]);
    mockedFetchFilePackage.mockResolvedValue(await makeTestPackage(ownerKeys, fileId, 1, plain));
    const confirm = vi.fn(() => false);
    vi.stubGlobal("window", { confirm });

    await expect(shareFile(ownerKeys, "alice", fileId, "carol")).rejects.toThrow(
      "Verificación de huella cancelada",
    );
    expect(mockedApi).not.toHaveBeenCalledWith("POST", expect.stringContaining("/share"), expect.anything());
  });

  it("re-encrypts a new version for the owner and remaining users, excluding the revoked user", async () => {
    installApiResponses(["alice", "bob", "carol"]);
    const oldPackage = await makeTestPackage(ownerKeys, fileId, 1, plain);
    mockedFetchFilePackage.mockResolvedValue(oldPackage);

    await revokeAccess(ownerKeys, "alice", fileId, "bob");

    const put = mockedApi.mock.calls.find(([method, path]) => method === "PUT" && path === `/files/${fileId}`);
    expect(put).toBeDefined();
    const form = put?.[2] as FormData;
    expect(form.get("version")).toBe("2");
    const wrappedDeks = JSON.parse(form.get("wrapped_deks") as string) as Array<{
      username: string;
      wrapped_dek: string;
    }>;
    expect(wrappedDeks.map(({ username }) => username).sort()).toEqual(["alice", "carol"]);
    expect(JSON.parse(form.get("audit") as string)).toEqual(audit);

    const blob = form.get("blob") as Blob;
    const updatedPackage: FilePackage = {
      meta: {
        id: fileId,
        owner: "alice",
        version: 2,
        manifest: form.get("manifest") as string,
        manifest_signature: form.get("manifest_signature") as string,
        wrapped_dek: wrappedDeks.find(({ username }) => username === "carol")!.wrapped_dek,
      },
      blob: new Uint8Array(await blob.arrayBuffer()),
    };
    const result = await verifyAndDecrypt(
      remainingKeys,
      updatedPackage,
      ownerKeys.sigSpki,
      "carol",
    );
    expect([...result.plain]).toEqual([...plain]);
    expect(result.m.version).toBe(2);
    await expect(
      crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        revokedKeys.encPrivate,
        fromB64(updatedPackage.meta.wrapped_dek),
      ),
    ).rejects.toThrow();
  });

  it("rejects revoking someone who has no access before preparing an update", async () => {
    installApiResponses(["alice"]);

    await expect(revokeAccess(ownerKeys, "alice", fileId, "bob")).rejects.toThrow(
      "no tiene acceso",
    );
    expect(mockedFetchFilePackage).not.toHaveBeenCalled();
    expect(mockedApi.mock.calls.some(([method]) => method === "PUT")).toBe(false);
  });

  it("reuses a previously trusted fingerprint without prompting again", async () => {
    installApiResponses([]);
    const value = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => value.get(key) ?? null,
      setItem: (key: string, entry: string) => value.set(key, entry),
    });
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    const sig = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    mockedApi.mockImplementation(async <T>(method: string, path: string): Promise<T> => {
      if (method === "GET" && path === "/keys/carol") {
        return {
          username: "carol",
          enc_public_key: toB64(await crypto.subtle.exportKey("spki", pair.publicKey)),
          sig_public_key: toB64(await crypto.subtle.exportKey("spki", sig.publicKey)),
          updated_at: "2026-01-01T00:00:00",
        } as T;
      }
      return { ok: true } as T;
    });
    await trustedKeys("alice", "carol");
    const firstConfirm = vi.mocked(window.confirm);
    await trustedKeys("alice", "CAROL");

    expect(firstConfirm).toHaveBeenCalledOnce();
  });
});
