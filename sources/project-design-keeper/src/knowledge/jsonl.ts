import { TextDecoder } from "node:util";
import { keeperLimits } from "../security/limits.js";
import { managedReadLimits } from "../settings/policy.js";

export type CanonicalJsonLinesErrorKind = "size" | "count" | "encoding" | "format" | "json";

export class CanonicalJsonLinesError extends Error {
  constructor(
    readonly kind: CanonicalJsonLinesErrorKind,
    message: string,
    readonly line?: number
  ) {
    super(message);
    this.name = "CanonicalJsonLinesError";
  }
}

export interface CanonicalJsonLine {
  value: unknown;
  line: number;
}

export function decodeCanonicalJsonLines(
  bytes: Buffer,
  label: string,
  options: {
    expectedCount?: unknown;
    maxBytes?: number;
    maxLines?: number;
  } = {}
): CanonicalJsonLine[] {
  const maxBytes = options.maxBytes ?? managedReadLimits.maxFileBytes;
  const maxLines = options.maxLines ?? keeperLimits.pack.maxRecords;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > managedReadLimits.maxFileBytes) {
    throw new CanonicalJsonLinesError("size", `${label} byte limit is invalid`);
  }
  if (!Number.isSafeInteger(maxLines) || maxLines < 0 || maxLines > keeperLimits.pack.maxRecords) {
    throw new CanonicalJsonLinesError("count", `${label} line limit is invalid`);
  }
  if (bytes.byteLength > maxBytes) {
    throw new CanonicalJsonLinesError("size", `${label} exceeds the JSONL file limit of ${maxBytes} bytes`);
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new CanonicalJsonLinesError("encoding", `${label} JSONL has a forbidden UTF-8 BOM`);
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CanonicalJsonLinesError("encoding", `${label} JSONL is not valid UTF-8`);
  }

  let lines: string[];
  if (text.length === 0) {
    lines = [];
  } else {
    if (!text.endsWith("\n") || text.endsWith("\n\n") || text.includes("\r")) {
      throw new CanonicalJsonLinesError(
        "format",
        `${label} JSONL must end with exactly one canonical LF and contain no CR characters`
      );
    }
    lines = text.slice(0, -1).split("\n");
    const blank = lines.findIndex((line) => line.trim().length === 0);
    if (blank >= 0) {
      throw new CanonicalJsonLinesError("format", `${label} JSONL has a blank line at ${blank + 1}`, blank + 1);
    }
    const padded = lines.findIndex((line) => line !== line.trim());
    if (padded >= 0) {
      throw new CanonicalJsonLinesError(
        "format",
        `${label} JSONL has noncanonical surrounding whitespace at line ${padded + 1}`,
        padded + 1
      );
    }
  }

  if (lines.length > maxLines) {
    throw new CanonicalJsonLinesError("count", `${label} exceeds the JSONL line limit of ${maxLines}`);
  }
  if (options.expectedCount !== undefined) {
    const expected = options.expectedCount;
    if (!Number.isSafeInteger(expected) || Number(expected) < 0 || Number(expected) > maxLines) {
      throw new CanonicalJsonLinesError("count", `${label} expected line count is invalid`);
    }
    if (lines.length !== expected) {
      throw new CanonicalJsonLinesError(
        "count",
        `${label} declares ${String(expected)} entries but contains ${lines.length}`
      );
    }
  }

  return lines.map((line, index) => {
    try {
      return { value: JSON.parse(line) as unknown, line: index + 1 };
    } catch {
      throw new CanonicalJsonLinesError("json", `${label} JSONL is malformed at line ${index + 1}`, index + 1);
    }
  });
}
