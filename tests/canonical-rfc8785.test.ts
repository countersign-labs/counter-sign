// Copyright 2026 Haridarman Kumaresan
// SPDX-License-Identifier: Apache-2.0
//
// CHARACTERIZATION SUITE for canonical JSON against RFC 8785 (JSON Canonicalization
// Scheme, JCS). These tests pin TODAY's behaviour of src/core/canonical.ts; they do
// not change it. Where the output already equals what RFC 8785 requires, the test
// says "matches RFC 8785". Where it differs, the test says "differs from RFC 8785"
// and records what JCS would do instead. See docs/proposals/0005-canonical-json-rfc8785.md.
// Every non-ASCII character in this file is written as an escape on purpose, so the
// cases stay readable and an editor cannot silently normalize them.

import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/core/canonical.js";

describe("canonical JSON vs RFC 8785: numbers", () => {
  // RFC 8785 section 3.2.2.3 serializes numbers exactly as ECMAScript
  // Number.prototype.toString, which is what JSON.stringify does for a finite number.
  it("matches RFC 8785: exponent form from 1e21 up, plain form below, shortest round-trip digits", () => {
    expect(canonicalize([1e21, 1e20, 1e30, 1.7976931348623157e308])).toBe(
      "[1e+21,100000000000000000000,1e+30,1.7976931348623157e+308]",
    );
    expect(canonicalize([1e-7, 1e-6, 5e-324, 0.1 + 0.2, 4.5, 2e-3])).toBe("[1e-7,0.000001,5e-324,0.30000000000000004,4.5,0.002]");
  });

  it("matches RFC 8785: negative zero serializes as 0, integral values carry no fraction", () => {
    expect(canonicalize({ z: -0, one: 1.0, hundred: 100 })).toBe('{"hundred":100,"one":1,"z":0}');
  });

  it("matches RFC 8785: non-finite numbers are an error, not a string", () => {
    expect(() => canonicalize(NaN)).toThrow(TypeError);
    expect(() => canonicalize(Infinity)).toThrow(TypeError);
    expect(() => canonicalize(-Infinity)).toThrow(TypeError);
  });

  it("matches RFC 8785 (I-JSON): integers beyond 2^53 have already lost precision when parsed", () => {
    // Both JCS and this implementation work on IEEE-754 doubles, so the parsed value is
    // what gets serialized. An implementation that keeps big integers exact (Python
    // ints, for example) differs here; the proposal records that.
    expect(canonicalize(JSON.parse("[9007199254740993]"))).toBe("[9007199254740992]");
  });

  it("refuses a BigInt rather than inventing a form (RFC 8785 has no BigInt)", () => {
    expect(() => canonicalize({ n: 1n })).toThrow(/bigint/);
  });
});

describe("canonical JSON vs RFC 8785: strings", () => {
  it("matches RFC 8785: short escapes for \\b \\t \\n \\f \\r, lowercase \\u00xx for other controls", () => {
    expect(canonicalize("\u0000\u0008\u0009\u000a\u000c\u000d\u001f")).toBe('"\\u0000\\b\\t\\n\\f\\r\\u001f"');
  });

  it("matches RFC 8785: DEL, U+2028, U+2029, '/' and non-ASCII are raw UTF-8, never escaped", () => {
    const s = "\u007f\u2028\u2029/\u00e9\u65e5\u{1f600}";
    expect(canonicalize(s)).toBe(`"${s}"`);
  });

  it("matches RFC 8785: quote and backslash are the only other escapes", () => {
    expect(canonicalize('a"b\\c')).toBe('"a\\"b\\\\c"');
  });

  it("differs from RFC 8785: a lone surrogate is escaped as \\udxxx instead of being refused", () => {
    // RFC 8785 requires I-JSON input, which forbids unpaired surrogates; a JCS
    // implementation must reject this value. canonical.ts follows well-formed
    // JSON.stringify (ES2019) and escapes it.
    expect(canonicalize("\ud800x\udc00")).toBe('"\\ud800x\\udc00"');
  });

  it("matches RFC 8785: no Unicode normalization, so NFC and NFD spellings stay distinct", () => {
    // Actor ids are NFC-normalized by normalizeActor before they are compared, but the
    // canonical form itself never normalizes; two visually equal keys both survive,
    // ordered by code unit ("e" U+0065 before U+00E9).
    expect(canonicalize({ "\u00e9": 2, "e\u0301": 1 })).toBe('{"e\u0301":1,"\u00e9":2}');
  });
});

describe("canonical JSON vs RFC 8785: object keys", () => {
  it("matches RFC 8785 section 3.2.3: keys sorted by UTF-16 code unit, the RFC's own example", () => {
    const value = {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\u{1f600}": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis",
    };
    // Read the order off the string: Object.keys on a parsed object would list the
    // integer-like key "1" first, whatever the text order.
    expect(canonicalize(value)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",' +
        '"\u20ac":"Euro Sign","\u{1f600}":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  it("matches RFC 8785: UTF-16 order, not code-point order, for astral vs high-BMP keys", () => {
    // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FB33 by code unit
    // although its code point is larger. Code-point (or UTF-8 byte) sorting would flip it.
    expect(canonicalize({ "\ufb33": 1, "\u{1f600}": 2 })).toBe('{"\u{1f600}":2,"\ufb33":1}');
  });

  it("differs from RFC 8785: a duplicate key in received JSON is silently last-wins, not refused", () => {
    // canonicalize works on a parsed value, so the duplicate is gone before it runs.
    // RFC 8785 requires I-JSON input, where duplicate names MUST be rejected; a
    // verifier that wants JCS behaviour has to detect duplicates while parsing.
    expect(canonicalize(JSON.parse('{"a":1,"a":2}'))).toBe('{"a":2}');
  });

  it("treats a parsed __proto__ member as an ordinary key", () => {
    expect(canonicalize(JSON.parse('{"__proto__":{"x":1},"b":2}'))).toBe('{"__proto__":{"x":1},"b":2}');
  });
});

describe("canonical JSON vs RFC 8785: the RFC's sample input", () => {
  it("matches RFC 8785 section 3.2.4 byte for byte", () => {
    const input =
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
      '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}';
    expect(canonicalize(JSON.parse(input))).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });
});

describe("canonical JSON: JavaScript-only inputs (no RFC 8785 counterpart)", () => {
  it("does not call toJSON: a Date or a Map canonicalizes as an empty object", () => {
    // JSON.stringify would call Date.prototype.toJSON; canonicalize walks own keys only.
    // Callers must pass ISO strings, as createIntent does for created_at.
    expect(canonicalize({ d: new Date(0) })).toBe('{"d":{}}');
    expect(canonicalize(new Map([["a", 1]]))).toBe("{}");
  });

  it("writes undefined in an array as null and drops it from an object", () => {
    expect(canonicalize({ a: [undefined, 1], b: undefined })).toBe('{"a":[null,1]}');
  });

  it("refuses nesting deeper than 64 (RFC 8785 sets no limit)", () => {
    let deep: unknown = 1;
    for (let i = 0; i < 70; i++) deep = [deep];
    expect(() => canonicalize(deep)).toThrow(RangeError);
  });
});
