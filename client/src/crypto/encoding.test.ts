import { describe, expect, it } from "vitest";
import { fromHex } from "./encoding";

describe("fromHex", () => {
  it("decodes upper- and lowercase hexadecimal bytes", () => {
    expect([...fromHex("00aBff")]).toEqual([0, 171, 255]);
  });

  it("accepts an empty string", () => {
    expect(fromHex("")).toEqual(new Uint8Array());
  });

  it.each(["f", "0g", "0x12", "12 34"])("rejects malformed input %j", (value) => {
    expect(() => fromHex(value)).toThrow("Cadena hexadecimal inválida");
  });
});
