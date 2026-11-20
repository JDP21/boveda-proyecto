// Runtime validation coverage for: encrypted file integrity and rollback protection
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { getSeenVersion, recordSeenVersion, verifyAndDecrypt } from "./envelope";
import { makeTestKeys, makeTestPackage } from "../test-utils/files";
import type { Keys } from "./keys";

const storage = new Map<string, string>();
let keys: Keys;
const fileId = "file-123";
const plain = new TextEncoder().encode("contenido privado");

describe("file envelope verification", () => {
  beforeAll(async () => {
    keys = await makeTestKeys();
  });

  beforeEach(() => {
    storage.clear();
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("decrypts an untampered file and persists the version per account", async () => {
    const pkg = await makeTestPackage(keys, fileId, 1, plain);

    const result = await verifyAndDecrypt(keys, pkg, keys.sigSpki, "Alice");

    expect([...result.plain]).toEqual([...plain]);
    expect(result.m).toMatchObject({ id: fileId, version: 1, name: "test.txt" });
    expect(getSeenVersion("alice", fileId)).toBe(1);
    expect(getSeenVersion("bob", fileId)).toBe(0);
  });

  it("rejects a blob whose bytes differ from the signed manifest hash", async () => {
    const pkg = await makeTestPackage(keys, fileId, 1, plain);
    const changedBlob = new Uint8Array(pkg.blob);
    changedBlob[changedBlob.length - 1] ^= 1;

    await expect(
      verifyAndDecrypt(keys, { ...pkg, blob: changedBlob }, keys.sigSpki, "alice"),
    ).rejects.toThrow("hash SHA-256");
  });

  it("rejects metadata whose signature is invalid", async () => {
    const pkg = await makeTestPackage(keys, fileId, 1, plain);

    await expect(
      verifyAndDecrypt(
        keys,
        { ...pkg, meta: { ...pkg.meta, manifest_signature: "invalid" } },
        keys.sigSpki,
        "alice",
      ),
    ).rejects.toThrow("Firma del manifiesto inválida");
  });

  it("rejects a version older than the highest version previously verified", async () => {
    const newer = await makeTestPackage(keys, fileId, 2, plain);
    const older = await makeTestPackage(keys, fileId, 1, plain);
    await verifyAndDecrypt(keys, newer, keys.sigSpki, "alice");

    await expect(
      verifyAndDecrypt(keys, older, keys.sigSpki, "alice"),
    ).rejects.toThrow("Rollback detectado");
  });

  it("keeps the highest recorded version for each account and file", () => {
    recordSeenVersion("Alice", fileId, 3);
    recordSeenVersion("alice", fileId, 2);
    recordSeenVersion("alice", "other-file", 1);
    recordSeenVersion("bob", fileId, 4);

    expect(getSeenVersion("alice", fileId)).toBe(3);
    expect(getSeenVersion("alice", "other-file")).toBe(1);
    expect(getSeenVersion("bob", fileId)).toBe(4);
  });
});
