# 0005 · Pinning canonical JSON to RFC 8785

**Status:** proposal, not applied · **Against:** spec v0.2 · **Raised by:** Kaviyam, the first reference deployment · 2026-11-17

## The problem, as met

Spec §1 defines canonical JSON in one sentence: keys sorted lexicographically at
every depth, no insignificant whitespace, UTF-8. `docs/security-review.md` already
says this must be pinned to RFC 8785 (JCS) before other-language implementations
are relied on. Kaviyam is Python. It hashes its own content with the same rules to
build the digest it puts in `action` (proposal 0001), and its review found that
`json.dumps(sort_keys=True)` and the Python client's `canonicalize` disagree on
floats (`8.0` against `8`). If an auditor in Node recomputes a digest that Python
made, both must give the same bytes for every value that can appear.

## Where `src/core/canonical.ts` stands against RFC 8785 today

Each line below is pinned by a test in `tests/canonical-rfc8785.test.ts`; nothing
was changed.

**Already the same as RFC 8785**

- **Numbers.** `JSON.stringify(number)` is ECMAScript `Number.prototype.toString`,
  which is exactly RFC 8785 §3.2.2.3: `1e+21` from 1e21 up, plain digits below,
  `1e-7` but `0.000001`, shortest round-trip digits (`0.30000000000000004`),
  `-0` as `0`, no trailing `.0`. Non-finite numbers are an error, as in JCS.
- **Strings.** Only `"` and the backslash are escaped, plus controls below U+0020:
  short forms for backspace, tab, newline, form feed and carriage return, and
  lowercase four-digit backslash-u escapes for the rest. DEL, U+2028, U+2029, `/`
  and all non-ASCII text are written as raw UTF-8. This is RFC 8785 §3.2.2.2.
- **Key order.** `Array.prototype.sort()` on the keys compares UTF-16 code units,
  which is RFC 8785 §3.2.3. This matters for non-ASCII keys: U+1F600 (surrogates
  D83D DE00) sorts before U+FB33 although its code point is larger. The RFC's own
  seven-key example and its §3.2.4 sample both come out byte for byte.
- **No Unicode normalization**, as in JCS: NFC and NFD spellings of a key stay two
  keys. (Actor ids are NFC-normalized before comparison, but that is outside
  canonicalization.)

**Where it differs, or could**

- **Lone surrogates** are escaped (well-formed `JSON.stringify`) instead of
  refused. RFC 8785 requires I-JSON input, which forbids them.
- **Duplicate keys** in received JSON are resolved last-wins by `JSON.parse`
  before canonicalization runs; JCS input must not contain them.
- **JavaScript-only inputs:** `toJSON` is not called (a `Date` becomes `{}`),
  `undefined` is dropped from objects and becomes `null` in arrays, BigInt is
  refused, and nesting deeper than 64 is refused. None of these exist in JSON.
- **The Python client** (`clients/python/countersign/canonical.py`) differs from
  both for floats: an integral float at or above 1e21 prints every digit
  (`1000000000000000000000`, not `1e+21`), exponents keep a leading zero (`1e-07`,
  not `1e-7`), small values use exponent form where JS does not (`1e-06`, not
  `0.000001`), and Python ints above 2^53 stay exact where JS has already rounded.
  A lone surrogate makes the Python output impossible to encode as UTF-8, so
  signing fails rather than diverging. The key order matches.

No v0.2 envelope reaches any of the differences: every key is fixed ASCII and every
number is a small integer (`quorum`, `timeout`, `seq`, `length`).

**Addition: a lone surrogate in an Intent's text.** Every key is ASCII, but the
values are not: `summary`, `action`, `callback`, `agent.id` and approver actors are
free text, so a lone surrogate does reach a v0.2 envelope. Today the two
implementations part ways on it:

- The reference's `createIntent` accepts `summary: "lone \ud800 s"`. The canonical
  form escapes it (`"lone \ud800 s"` as six ASCII characters), the signature
  covers those bytes, and `verifyIntent` accepts the result. Nothing is ambiguous:
  a summary holding the six literal characters gives different canonical bytes and
  does not verify with that signature.
- The Python client's `create_intent` refuses it with `CountersignError`
  ("Intent contains a lone surrogate (summary, U+D800) ..."); before, it raised a
  raw `UnicodeEncodeError`. It cannot produce the reference's bytes without
  escaping lone surrogates the way the reference does.

Such an Intent is also a problem downstream: the text cannot be shown to an
approver as written (chat platforms replace or refuse it), and a JSON file written
by a strict encoder may not round-trip. Under Option 1 the reference would refuse
it in `createIntent` and in verification, matching the Python client; that is a
behaviour change for the reference and is left to this proposal, not made now.

## Options

1. **Pin to RFC 8785 normatively**, with an explicit I-JSON input rule (reject lone
   surrogates and duplicate keys), and keep the depth limit as a stated
   implementation limit.
2. **Restrict the data model** instead: signed envelopes may contain only strings,
   booleans, null, safe integers, arrays and objects, never floats.
3. Both.

## Recommendation

Option 3. Pinning to RFC 8785 costs nothing, since the TypeScript output already
matches it for every valid I-JSON value; refusing floats in envelopes removes the
one area where hand-rolled implementations usually slip. Fix the Python client's
float formatting at the same time (or refuse floats there too), and add the RFC's
own examples to the vectors.

## Wire and vectors

No change for any existing envelope or vector. New `canonical` vectors: the RFC
§3.2.3 key-order example, the §3.2.4 sample, and the number cases above. A
verifier must refuse a lone surrogate or a duplicate key: new negative vectors,
which needs the vector format to carry raw JSON text rather than a parsed value.

## What integrators can do today

Use the library's `canonicalize` (or the Python client's) rather than
`json.dumps`, and keep floats out of anything you hash or sign: write amounts and
scores as integers or strings.
