import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import { canonicalJSON, enc, fromHex, sha256Hex, toB64 } from "../crypto/encoding";
import { signText } from "../crypto/sign";
import { makeTestKeys } from "../test-keys";
import {
  buildAuditEntry,
  fetchAuditLog,
  GENESIS_HASH,
  logAudit,
  verifyFullAuditChain,
  type AuditRecord,
} from "./api";

vi.mock("../api", () => ({ api: vi.fn() }));

const mockedApi = vi.mocked(api);

async function makeRecord(
  seq: number,
  prevHash: string,
  keys: Awaited<ReturnType<typeof makeTestKeys>>,
): Promise<AuditRecord> {
  const event = canonicalJSON({ action: "upload", file: `file-${seq}` });
  const entryHash = await sha256Hex(
    new Uint8Array([...fromHex(prevHash), ...enc.encode(event)]),
  );
  return {
    seq,
    actor: "alice",
    event,
    prev_hash: prevHash,
    entry_hash: entryHash,
    signature: await signText(keys.sigPrivate, entryHash),
    signer_key: keys.sigSpki,
    created_at: "2026-01-01T00:00:00",
  };
}

describe("client audit API", () => {
  beforeEach(() => {
    vi.useRealTimers();
    vi.resetAllMocks();
  });

  it("builds a canonical entry from the current head and signs its hash", async () => {
    const keys = await makeTestKeys();
    mockedApi.mockResolvedValueOnce({ seq: 0, hash: GENESIS_HASH });
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-02-03T04:05:06.000Z"));

    const entry = await buildAuditEntry(keys, { action: "upload", actor: "alice" });
    const expectedEvent = canonicalJSON({
      action: "upload",
      actor: "alice",
      ts: "2026-02-03T04:05:06.000Z",
    });
    const expectedHash = await sha256Hex(
      new Uint8Array([...fromHex(GENESIS_HASH), ...enc.encode(expectedEvent)]),
    );
    const publicKey = await crypto.subtle.importKey(
      "spki",
      Uint8Array.from(atob(keys.sigSpki), (c) => c.charCodeAt(0)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    expect(mockedApi).toHaveBeenCalledWith("GET", "/audit/head");
    expect(entry).toMatchObject({ event: expectedEvent, prev_hash: GENESIS_HASH, entry_hash: expectedHash });
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        Uint8Array.from(atob(entry.signature), (c) => c.charCodeAt(0)),
        enc.encode(expectedHash),
      ),
    ).toBe(true);
  });

  it("rebuilds and retries an entry when the server reports a stale head", async () => {
    const keys = await makeTestKeys();
    const nextHead = "a".repeat(64);
    let headReads = 0;
    let postCount = 0;
    const posted: Array<{ prev_hash: string }> = [];
    mockedApi.mockImplementation(async <T>(method: string, _path: string, body?: unknown) => {
      if (method === "GET") {
        const head = headReads++ === 0 ? GENESIS_HASH : nextHead;
        return { seq: headReads - 1, hash: head } as T;
      }
      postCount++;
      posted.push(body as { prev_hash: string });
      if (postCount === 1) throw new Error("409: stale");
      return { ok: true } as T;
    });

    await logAudit(keys, { action: "download", file: "file-1" });

    expect(headReads).toBe(2);
    expect(posted).toHaveLength(2);
    expect(posted.map((entry) => entry.prev_hash)).toEqual([GENESIS_HASH, nextHead]);
  });

  it("returns an empty valid chain", async () => {
    await expect(verifyFullAuditChain([])).resolves.toEqual({ ok: true, count: 0 });
  });

  it("verifies a valid chain and reports broken links, hashes, and signatures", async () => {
    const keys = await makeTestKeys();
    const first = await makeRecord(1, GENESIS_HASH, keys);
    const second = await makeRecord(2, first.entry_hash, keys);

    await expect(verifyFullAuditChain([first, second])).resolves.toEqual({ ok: true, count: 2 });
    await expect(
      verifyFullAuditChain([first, { ...second, prev_hash: GENESIS_HASH }]),
    ).resolves.toEqual({ ok: false, brokenAt: 2, reason: "prev_hash" });
    await expect(
      verifyFullAuditChain([{ ...first, entry_hash: `${first.entry_hash[0] === "0" ? "1" : "0"}${first.entry_hash.slice(1)}` }]),
    ).resolves.toEqual({ ok: false, brokenAt: 1, reason: "entry_hash" });
    await expect(
      verifyFullAuditChain([{ ...first, signature: toB64(new Uint8Array([1])) }]),
    ).resolves.toEqual({ ok: false, brokenAt: 1, reason: "signature" });
  });

  it("retrieves the audit log endpoint", async () => {
    const records: AuditRecord[] = [];
    mockedApi.mockResolvedValueOnce(records);

    await expect(fetchAuditLog()).resolves.toBe(records);
    expect(mockedApi).toHaveBeenCalledWith("GET", "/audit");
  });
});
