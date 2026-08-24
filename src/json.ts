/**
 * AegisBench — AB-JCS-1 strict JSON input layer (M0 Slice 1).
 *
 * Contract references: MASTER_PROMPT.md §7 (duplicate-key rejection BEFORE
 * normal object materialization; I-JSON data constraints; finite numbers;
 * depth/document/string/array size limits; Unicode scalar values only).
 *
 * Binding numeric parameters are pinned in docs/implementation-plan.md:
 *   maxDocumentBytes=1048576, maxDepth=64, maxStringBytes=65536,
 *   maxContainerMembers=10000. `-0` is rejected at parse time.
 *
 * Zero runtime dependencies: Node built-ins only. Erasable TS syntax only
 * (Node 22 strip-only mode, verified by probe 2026-08-24).
 */

/** Hard limits for the strict parser. Frozen at module load; never mutated. */
export const STRICT_LIMITS = {
  /** Maximum whole-document size in UTF-8 bytes (1 MiB). */
  maxDocumentBytes: 1_048_576,
  /** Maximum nesting depth counted in containers (arrays/objects). */
  maxDepth: 64,
  /** Maximum single string length in UTF-8 bytes. */
  maxStringBytes: 65_536,
  /** Maximum members of one array or object. */
  maxContainerMembers: 10_000,
} as const;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type StrictJsonErrorCode =
  | "E_EMPTY_INPUT"
  | "E_BOM"
  | "E_DOCUMENT_TOO_LARGE"
  | "E_MALFORMED"
  | "E_TRAILING_CONTENT"
  | "E_DEPTH_EXCEEDED"
  | "E_CONTAINER_TOO_LARGE"
  | "E_DUPLICATE_KEY"
  | "E_STRING_TOO_LONG"
  | "E_CONTROL_CHAR_IN_STRING"
  | "E_BAD_ESCAPE"
  | "E_LONE_SURROGATE"
  | "E_NONFINITE_NUMBER"
  | "E_NEGATIVE_ZERO";

export interface StrictJsonError {
  readonly code: StrictJsonErrorCode;
  readonly message: string;
  /** 1-based line (LF, CRLF, and CR each end a line). */
  readonly line: number;
  /** 1-based column in UTF-16 code units within the line. */
  readonly column: number;
  /** Object-member path where the failure occurred, e.g. `$.evidence[2].id`. */
  readonly path?: string;
}

export type StrictParseResult =
  | { readonly ok: true; readonly value: JsonValue }
  | { readonly ok: false; readonly errors: readonly StrictJsonError[] };

const utf8Encoder = new TextEncoder();

function utf8Len(s: string): number {
  return utf8Encoder.encode(s).length;
}

interface Ctx {
  readonly text: string;
  pos: number;
  depth: number;
}

class StrictParseFailure extends Error {
  readonly failure: StrictJsonError;
  constructor(failure: StrictJsonError) {
    super(failure.message);
    this.failure = failure;
  }
}

function fail(
  ctx: Ctx,
  code: StrictJsonErrorCode,
  message: string,
  path?: string,
): never {
  let line = 1;
  let lastLineStart = 0;
  const upto = Math.min(ctx.pos, ctx.text.length);
  for (let i = 0; i < upto; i++) {
    const ch = ctx.text.charCodeAt(i);
    if (ch === 0x0a) {
      line++;
      lastLineStart = i + 1;
    } else if (ch === 0x0d) {
      if (i + 1 < upto && ctx.text.charCodeAt(i + 1) === 0x0a) continue; // CRLF counted at LF
      line++;
      lastLineStart = i + 1;
    }
  }
  throw new StrictParseFailure({
    code,
    message,
    line,
    column: upto - lastLineStart + 1,
    ...(path === undefined ? {} : { path }),
  });
}

function skipWs(ctx: Ctx): void {
  while (ctx.pos < ctx.text.length) {
    const c = ctx.text.charCodeAt(ctx.pos);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) ctx.pos++;
    else break;
  }
}

const HEX_DIGITS = "0123456789abcdefABCDEF";

function hexValue(ch: string): number {
  const idx = HEX_DIGITS.indexOf(ch);
  if (idx < 0) return -1;
  return idx <= 15 ? idx : idx - 6; // 'A'-('a'-10): map A-F onto 10-15
}

/** Parses one \uXXXX escape; ctx.pos points AT the 'u'. Returns the code unit. */
function readUnicodeEscape(ctx: Ctx, path: string): number {
  let code = 0;
  for (let k = 1; k <= 4; k++) {
    const ch = ctx.text.charAt(ctx.pos + k);
    const v = hexValue(ch);
    if (v < 0) {
      fail(ctx, "E_BAD_ESCAPE", `Invalid \\u escape near offset ${ctx.pos}`, path);
    }
    code = code * 16 + v;
  }
  ctx.pos += 5;
  return code;
}

function readString(ctx: Ctx, path: string): string {
  ctx.pos++; // consume opening quote
  const parts: string[] = [];
  for (;;) {
    if (ctx.pos >= ctx.text.length) {
      fail(ctx, "E_MALFORMED", "Unterminated string literal", path);
    }
    const c = ctx.text.charCodeAt(ctx.pos);
    if (c === 0x22) {
      ctx.pos++;
      break;
    }
    if (c < 0x20) {
      fail(
        ctx,
        "E_CONTROL_CHAR_IN_STRING",
        `Unescaped control character U+${c.toString(16).padStart(4, "0")} in string`,
        path,
      );
    }
    if (c === 0x5c) {
      ctx.pos++;
      if (ctx.pos >= ctx.text.length) {
        fail(ctx, "E_BAD_ESCAPE", "Escape at end of input", path);
      }
      const e = ctx.text.charAt(ctx.pos);
      switch (e) {
        case '"':
          parts.push('"');
          ctx.pos++;
          break;
        case "\\":
          parts.push("\\");
          ctx.pos++;
          break;
        case "/":
          parts.push("/");
          ctx.pos++;
          break;
        case "b":
          parts.push("\b");
          ctx.pos++;
          break;
        case "f":
          parts.push("\f");
          ctx.pos++;
          break;
        case "n":
          parts.push("\n");
          ctx.pos++;
          break;
        case "r":
          parts.push("\r");
          ctx.pos++;
          break;
        case "t":
          parts.push("\t");
          ctx.pos++;
          break;
        case "u": {
          const cu = readUnicodeEscape(ctx, path);
          if (cu >= 0xd800 && cu <= 0xdbff) {
            // After readUnicodeEscape, ctx.pos points at the NEXT character,
            // which must be the second escape's backslash for a valid pair.
            if (
              ctx.text.charCodeAt(ctx.pos) === 0x5c &&
              ctx.text.charAt(ctx.pos + 1) === "u"
            ) {
              ctx.pos++; // advance from '\' onto 'u'
              const lo = readUnicodeEscape(ctx, path);
              if (lo >= 0xdc00 && lo <= 0xdfff) {
                parts.push(
                  String.fromCodePoint(0x10000 + ((cu - 0xd800) << 10) + (lo - 0xdc00)),
                );
              } else {
                fail(
                  ctx,
                  "E_LONE_SURROGATE",
                  "High surrogate escape not followed by low surrogate escape",
                  path,
                );
              }
            } else {
              fail(
                ctx,
                "E_LONE_SURROGATE",
                "High surrogate escape not followed by low surrogate escape",
                path,
              );
            }
          } else if (cu >= 0xdc00 && cu <= 0xdfff) {
            fail(ctx, "E_LONE_SURROGATE", "Lone low surrogate escape", path);
          } else {
            parts.push(String.fromCharCode(cu));
          }
          break;
        }
        default:
          fail(ctx, "E_BAD_ESCAPE", `Invalid escape character "${e}"`, path);
      }
      continue;
    }
    // Plain character run up to the next quote, backslash, or control char.
    const start = ctx.pos;
    while (ctx.pos < ctx.text.length) {
      const cc = ctx.text.charCodeAt(ctx.pos);
      if (cc === 0x22 || cc === 0x5c || cc < 0x20) break;
      ctx.pos++;
    }
    parts.push(ctx.text.slice(start, ctx.pos));
  }
  const s = parts.join("");
  assertNoLoneSurrogates(ctx, s, path);
  if (utf8Len(s) > STRICT_LIMITS.maxStringBytes) {
    fail(
      ctx,
      "E_STRING_TOO_LONG",
      `String exceeds ${STRICT_LIMITS.maxStringBytes} UTF-8 bytes`,
      path,
    );
  }
  return s;
}

/** I-JSON: strings must contain Unicode scalar values only (no lone surrogates). */
function assertNoLoneSurrogates(ctx: Ctx, s: string, path: string): void {
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      const nxt = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (!(nxt >= 0xdc00 && nxt <= 0xdfff)) {
        fail(
          ctx,
          "E_LONE_SURROGATE",
          "String contains a lone high surrogate (I-JSON requires scalar values)",
          path,
        );
      }
      i++;
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      fail(
        ctx,
        "E_LONE_SURROGATE",
        "String contains a lone low surrogate (I-JSON requires scalar values)",
        path,
      );
    }
  }
}

function readNumber(ctx: Ctx, path: string): number {
  const start = ctx.pos;
  if (ctx.text.charAt(ctx.pos) === "-") ctx.pos++;
  // Integer part: "0" or [1-9][0-9]*.
  if (ctx.text.charAt(ctx.pos) === "0") {
    ctx.pos++;
  } else if (ctx.text.charAt(ctx.pos) >= "1" && ctx.text.charAt(ctx.pos) <= "9") {
    while (ctx.text.charAt(ctx.pos) >= "0" && ctx.text.charAt(ctx.pos) <= "9") ctx.pos++;
  } else {
    fail(ctx, "E_MALFORMED", "Invalid number literal", path);
  }
  if (ctx.text.charAt(ctx.pos) === ".") {
    ctx.pos++;
    const fracStart = ctx.pos;
    while (ctx.text.charAt(ctx.pos) >= "0" && ctx.text.charAt(ctx.pos) <= "9") ctx.pos++;
    if (ctx.pos === fracStart) fail(ctx, "E_MALFORMED", "Fraction digit expected", path);
  }
  const ec = ctx.text.charAt(ctx.pos);
  if (ec === "e" || ec === "E") {
    ctx.pos++;
    const sc = ctx.text.charAt(ctx.pos);
    if (sc === "+" || sc === "-") ctx.pos++;
    const expStart = ctx.pos;
    while (ctx.text.charAt(ctx.pos) >= "0" && ctx.text.charAt(ctx.pos) <= "9") ctx.pos++;
    if (ctx.pos === expStart) fail(ctx, "E_MALFORMED", "Exponent digit expected", path);
  }
  const lexeme = ctx.text.slice(start, ctx.pos);
  const n = Number(lexeme);
  if (!Number.isFinite(n)) {
    fail(ctx, "E_NONFINITE_NUMBER", `Number is outside the finite range: ${lexeme}`, path);
  }
  if (Object.is(n, -0)) {
    fail(ctx, "E_NEGATIVE_ZERO", "Negative zero (-0) is rejected by AB-JCS-1", path);
  }
  return n;
}

function readLiteral(ctx: Ctx, word: string, value: JsonValue, path: string): JsonValue {
  if (ctx.text.startsWith(word, ctx.pos)) {
    ctx.pos += word.length;
    return value;
  }
  fail(ctx, "E_MALFORMED", `Invalid literal near offset ${ctx.pos}`, path);
}

function parseValue(ctx: Ctx, path: string): JsonValue {
  skipWs(ctx);
  if (ctx.pos >= ctx.text.length) {
    fail(ctx, "E_MALFORMED", "Unexpected end of input", path);
  }
  const c = ctx.text.charAt(ctx.pos);
  if (c === "{") {
    enforceDepth(ctx, path);
    ctx.depth++;
    ctx.pos++; // consume '{'
    const obj: { [key: string]: JsonValue } = {};
    const seen = new Set<string>();
    skipWs(ctx);
    if (ctx.text.charAt(ctx.pos) === "}") {
      ctx.pos++;
      ctx.depth--;
      return obj;
    }
    for (;;) {
      skipWs(ctx);
      if (ctx.text.charAt(ctx.pos) !== '"') {
        fail(ctx, "E_MALFORMED", "Object key must be a string", path);
      }
      const key = readString(ctx, path);
      // Duplicate-key rejection happens HERE — while walking the raw text,
      // before the member value is parsed and materialized into the object
      // under construction. The duplicated key is identified by path.
      if (seen.has(key)) {
        fail(ctx, "E_DUPLICATE_KEY", `Duplicate object key "${key}"`, `${path}.${key}`);
      }
      seen.add(key);
      skipWs(ctx);
      if (ctx.text.charAt(ctx.pos) !== ":") {
        fail(ctx, "E_MALFORMED", "Expected ':' after object key", `${path}.${key}`);
      }
      ctx.pos++;
      obj[key] = parseValue(ctx, `${path}.${key}`);
      if (seen.size > STRICT_LIMITS.maxContainerMembers) {
        fail(
          ctx,
          "E_CONTAINER_TOO_LARGE",
          `Object exceeds ${STRICT_LIMITS.maxContainerMembers} members`,
          path,
        );
      }
      skipWs(ctx);
      const sep = ctx.text.charAt(ctx.pos);
      if (sep === ",") {
        ctx.pos++;
        continue;
      }
      if (sep === "}") {
        ctx.pos++;
        break;
      }
      fail(ctx, "E_MALFORMED", "Expected ',' or '}' in object", path);
    }
    ctx.depth--;
    return obj;
  }
  if (c === "[") {
    enforceDepth(ctx, path);
    ctx.depth++;
    ctx.pos++; // consume '['
    const arr: JsonValue[] = [];
    skipWs(ctx);
    if (ctx.text.charAt(ctx.pos) === "]") {
      ctx.pos++;
      ctx.depth--;
      return arr;
    }
    for (;;) {
      if (arr.length >= STRICT_LIMITS.maxContainerMembers) {
        fail(
          ctx,
          "E_CONTAINER_TOO_LARGE",
          `Array exceeds ${STRICT_LIMITS.maxContainerMembers} items`,
          path,
        );
      }
      arr.push(parseValue(ctx, `${path}[${arr.length}]`));
      skipWs(ctx);
      const sep = ctx.text.charAt(ctx.pos);
      if (sep === ",") {
        ctx.pos++;
        continue;
      }
      if (sep === "]") {
        ctx.pos++;
        break;
      }
      fail(ctx, "E_MALFORMED", "Expected ',' or ']' in array", path);
    }
    ctx.depth--;
    return arr;
  }
  if (c === '"') return readString(ctx, path);
  if (c === "-" || (c >= "0" && c <= "9")) return readNumber(ctx, path);
  if (c === "t") return readLiteral(ctx, "true", true, path);
  if (c === "f") return readLiteral(ctx, "false", false, path);
  if (c === "n") return readLiteral(ctx, "null", null, path);
  fail(ctx, "E_MALFORMED", `Unexpected character "${c}"`, path);
}

/** Containers only: a scalar leaf at maxDepth is legal; one more container is not. */
function enforceDepth(ctx: Ctx, path: string): void {
  if (ctx.depth >= STRICT_LIMITS.maxDepth) {
    fail(
      ctx,
      "E_DEPTH_EXCEEDED",
      `Nesting exceeds maximum depth ${STRICT_LIMITS.maxDepth}`,
      path,
    );
  }
}

/**
 * Parse JSON text under AB-JCS-1 input constraints.
 *
 * Duplicate object keys are detected while walking the raw text, before the
 * containing object is materialized; the returned failure identifies the
 * duplicated key path. On any failure, no partial object escapes this function.
 */
export function parseStrict(text: string): StrictParseResult {
  try {
    if (text.length === 0) {
      return {
        ok: false,
        errors: [
          { code: "E_EMPTY_INPUT", message: "Input is empty", line: 1, column: 1 },
        ],
      };
    }
    if (text.charCodeAt(0) === 0xfeff) {
      return {
        ok: false,
        errors: [
          {
            code: "E_BOM",
            message: "UTF-8 BOM is not permitted (I-JSON)",
            line: 1,
            column: 1,
          },
        ],
      };
    }
    const docBytes = utf8Len(text);
    if (docBytes > STRICT_LIMITS.maxDocumentBytes) {
      return {
        ok: false,
        errors: [
          {
            code: "E_DOCUMENT_TOO_LARGE",
            message: `Document exceeds ${STRICT_LIMITS.maxDocumentBytes} UTF-8 bytes`,
            line: 1,
            column: 1,
          },
        ],
      };
    }
    const ctx: Ctx = { text, pos: 0, depth: 0 };
    const value = parseValue(ctx, "$");
    skipWs(ctx);
    if (ctx.pos !== text.length) {
      fail(ctx, "E_TRAILING_CONTENT", "Trailing content after top-level JSON value", "$");
    }
    return { ok: true, value };
  } catch (e) {
    if (e instanceof StrictParseFailure) {
      return { ok: false, errors: [e.failure] };
    }
    throw e;
  }
}
