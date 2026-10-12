import { gzipSync } from "node:zlib";
import { expect, test } from "vitest";
import { canonicalJsonChunks, decodeStoredText, encodeStoredText, textStorageLimits } from "../src/security/text-storage.js";

test("compressed strings roundtrip with literal reserved object keys", () => {
  const value = { text: "中😀\u0001".repeat(10000), nested: { $keeperCompressedText: { bytes: 7, data: "literal" } }, other: { $keeperLiteralObject: "literal" } };
  expect(decodeStoredText(encodeStoredText(value))).toEqual(value);
});

test("compressed strings preserve a leading UTF-8 BOM byte for byte", () => {
  const value = { text: "\uFEFF" + "知识".repeat(10000) };
  const decoded = decodeStoredText(encodeStoredText(value)) as typeof value;
  expect(Buffer.from(decoded.text)).toEqual(Buffer.from(value.text));
});

test("decompression rejects declared oversize and a compressed payload larger than its bound", () => {
  const encoded = (bytes: number) => ({ textStorage: "keeper-text-v1", payload: { $keeperCompressedText: { bytes, data: gzipSync(Buffer.alloc(1024 * 1024)).toString("base64") } } });
  expect(() => decodeStoredText(encoded(textStorageLimits.maxStringBytes + 1))).toThrow(/expanded byte budget/);
  expect(() => decodeStoredText(encoded(1))).toThrow();
});

test("streamed canonical JSON matches legacy JSON through astral chunk boundaries", () => {
  const value = { a: "a".repeat(65535) + "😀\u0001", z: { "2": "two", "10": "ten", a: undefined, b: [null, 1, "中"] } };
  expect([...canonicalJsonChunks(value)].join("")).toBe(JSON.stringify(value));
});
