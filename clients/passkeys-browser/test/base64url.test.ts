// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";
import * as b64u from "../src/base64url";

describe("base64url", () => {
  it("encodes Uint8Array with no padding", () => {
    expect(b64u.encode(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe("3q2-7w");
  });

  it("encodes ArrayBuffer", () => {
    const ab = new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer;
    expect(b64u.encode(ab)).toBe("AQIDBA");
  });

  it("encodes 1-byte (2-char output, no padding)", () => {
    expect(b64u.encode(new Uint8Array([0xff]))).toBe("_w");
  });

  it("encodes 2-byte (3-char output, no padding)", () => {
    expect(b64u.encode(new Uint8Array([0xff, 0xff]))).toBe("__8");
  });

  it("uses url-safe alphabet (- and _, not + and /)", () => {
    // 0xfb, 0xff produces "+/8=" in standard base64 → "-_8" url-safe + no pad.
    expect(b64u.encode(new Uint8Array([0xfb, 0xff, 0xfe]))).not.toContain("+");
    expect(b64u.encode(new Uint8Array([0xfb, 0xff, 0xfe]))).not.toContain("/");
    expect(b64u.encode(new Uint8Array([0xfb, 0xff, 0xfe]))).not.toContain("=");
  });

  it("decodes back to bytes", () => {
    expect(Array.from(b64u.decode("3q2-7w"))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("decodes with or without padding", () => {
    expect(Array.from(b64u.decode("AQIDBA"))).toEqual([1, 2, 3, 4]);
    expect(Array.from(b64u.decode("AQIDBA=="))).toEqual([1, 2, 3, 4]);
  });

  it("round trips random data", () => {
    const data = new Uint8Array(64);
    for (let i = 0; i < data.length; i++) data[i] = i * 7 + 3;
    expect(Array.from(b64u.decode(b64u.encode(data)))).toEqual(Array.from(data));
  });

  it("decodeToArrayBuffer returns ArrayBuffer", () => {
    const ab = b64u.decodeToArrayBuffer("3q2-7w");
    expect(ab).toBeInstanceOf(ArrayBuffer);
    expect(ab.byteLength).toBe(4);
  });

  // StrykerJS (PR #39, @bernata) flagged the input-type dispatch in toUint8Array.
  // Encoding a DataView (an ArrayBufferView that is neither Uint8Array nor
  // ArrayBuffer) exercises the third branch and kills the mutant that forces the
  // `instanceof ArrayBuffer` check true.
  it("encodes an ArrayBufferView (DataView) identically to the same bytes", () => {
    const buf = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer as ArrayBuffer;
    expect(b64u.encode(new DataView(buf))).toBe(b64u.encode(new Uint8Array(buf)));
    expect(b64u.encode(new DataView(buf))).toBe("3q2-7w");
  });

  it("encodes a Uint8Array view that has a non-zero byteOffset", () => {
    // Subarray view: byteOffset 1, length 2 — guards the Uint8Array branch
    // against being skipped in favour of a buffer-from-scratch reconstruction.
    const full = new Uint8Array([0x00, 0xde, 0xad, 0x00]);
    expect(b64u.encode(full.subarray(1, 3))).toBe(b64u.encode(new Uint8Array([0xde, 0xad])));
  });
});
