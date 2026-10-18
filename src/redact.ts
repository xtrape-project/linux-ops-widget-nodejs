import type { OutputPolicy } from './types.js';

export const DEFAULT_MAX_OUTPUT_BYTES = 65536;
const DEFAULT_PATTERNS = ['password', 'token', 'secret', 'private_key', 'authorization'];

/**
 * Redact sensitive values before output is logged, audited, or returned.
 *
 * Redaction does NOT truncate any more (#61 B, review 2382): the recording
 * ceiling is enforced exactly once, at the wire, where the bytes arrive — a
 * second, independently-defaulted cut here silently capped a deployment that
 * asked to record MORE than 64 KiB, and appended a note about a truncation
 * that had already been reported as a field. Two mechanisms for one decision
 * is one too many.
 */
export function redactOutput(output: string, policy?: OutputPolicy): string {
  const patterns = [...new Set([...DEFAULT_PATTERNS, ...(policy?.redact ?? [])])];
  let result = output;
  for (const pattern of patterns) {
    const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // key=value / key: value / "key": "value" forms
    result = result.replace(
      new RegExp(`(["']?[\\w.-]*${escaped}[\\w.-]*["']?\\s*[=:]\\s*)(["']?)[^\\s"',;]+(["']?)`, 'gi'),
      '$1$2***$3',
    );
  }
  return result;
}

/**
 * Drop a TRAILING incomplete UTF-8 sequence, keeping every whole character
 * (reviews 2382/2383).
 *
 * Decoding must happen on the assembled bytes, not chunk by chunk: a
 * multi-byte character split across two network chunks decodes to two
 * replacement characters if each chunk is decoded on its own. So the
 * executor accumulates raw bytes and calls this once, at the end — the only
 * incompleteness left is then at the ceiling cut, and dropping it is what
 * keeps the text whole and its byte count honest.
 */
export function trimIncompleteUtf8(buffer: Buffer): Buffer {
  // Walk back over continuation bytes (10xxxxxx) to the lead byte.
  let lead = buffer.byteLength - 1;
  while (lead >= 0 && ((buffer[lead] as number) & 0xc0) === 0x80) lead -= 1;
  if (lead < 0) return buffer.subarray(0, 0); // continuation bytes only: nothing whole
  const first = buffer[lead] as number;
  const expected = first < 0x80 ? 1 : first >= 0xf0 ? 4 : first >= 0xe0 ? 3 : first >= 0xc0 ? 2 : 0;
  // `expected === 0` is a stray continuation byte the walk could not resolve;
  // a sequence that is complete (or over-long, which the decoder will handle)
  // stays whole.
  if (expected !== 0 && lead + expected <= buffer.byteLength) return buffer;
  return buffer.subarray(0, lead);
}
