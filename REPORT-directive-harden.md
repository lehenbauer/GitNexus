# Swift conditional-directive preprocessing hardening

## Result

PASS. Defect D1 is fixed: indented `#if`/`#elseif`/`#else`/`#endif` lines are no longer blanked when they are inside regular or raw Swift multiline string literals. Test gap D3 is closed with direct scanner tests and a worker-pipeline fixture. The requested acceptance gates and both isolated CLI E2Es passed. No push was performed.

The existing provider registration remains active at `gitnexus/src/core/ingestion/languages/swift.ts:179-182`; no registration change was needed.

## Approach and scanner semantics

`gitnexus/src/core/ingestion/languages/swift/conditional-directive-preprocess.ts:1-171` now processes the source one line at a time. It retains a small lexical state across lines:

- `multilineStringPounds` is `null` outside a multiline string, `0` for `"""`, and the raw delimiter pound count for `#"""`, `##"""`, and so on. A raw string closes only on `"""` followed by exactly the same number of pounds.
- `blockCommentDepth` tracks nested `/* … */` comments so quote-like text in comments cannot open or close string state.
- Ordinary quoted strings, raw single-line strings, and `//` comments are skipped while scanning a line so their quote text cannot create a false multiline-string transition.
- A line is eligible for blanking only when the state at its start is outside a multiline string and the whole line is indent plus one of the four conditional directives. Only non-newline characters become spaces; `\r` and `\n` are copied unchanged.

Unterminated multiline strings are handled conservatively: after an opener with no matching close, all subsequent lines through EOF remain unchanged. This avoids rewriting possible string data and does not throw.

The scanner is intentionally not a full Swift parser. String interpolation expressions are not modeled with complete nesting fidelity; a nested multiline string inside an interpolation can still confuse this light scanner. This residual is documented in the implementation comment at lines 136-138.

Block-comment choice: comment interiors remain eligible for the existing directive blanking. The scanner does track nested comments, but only to keep comment contents from changing string state. This is safe because Swift parsers ignore comment interiors; the refutation probe showed no extraction change. The decision and rationale are documented at lines 133-136.

## Test inventory delta

- `gitnexus/test/unit/swift-conditional-directive-preprocess.test.ts:61-135` adds regular-string and raw-string identity coverage, including `#""" … """#` and `##""" … """##`, all four conditional-looking interior lines, a real directive between strings, unterminated EOF behavior, `#warning`/`#error`/`#available`/`#selector` preservation, and nested block-comment behavior.
- Existing mutation-sensitivity coverage for indented directives, top-level preservation, length/newline preservation, CRLF, offsets, and directive-free identity remains unchanged at `:5-59`.
- `gitnexus/test/integration/swift-conditional-directive.test.ts:56-83` adds the worker-pipeline E2E fixture. It verifies `StringHolder`, the `payload` property, and `afterString`, while comparing the exported preprocessor’s string interior byte-for-byte and exercising a real directive after the string.
- The implementation-round focused total increased from 182 to 187 tests: four new direct tests and one new pipeline test.

## Acceptance outputs

### Typecheck

Command:

```text
$ npx tsc --noEmit
exit=0
```

There was no diagnostic output.

### Build

Command:

```text
$ npm run build
```

Verbatim completion output:

```text
✓ built in 296ms
[plugin builtin:vite-reporter]
(!) Some chunks are larger than 500 kB after minification. Consider:
- Using dynamic import() to code-split the application
- Use build.rolldownOptions.output.codeSplitting to improve chunking
- Adjust chunk size limit via build.chunkSizeWarningLimit.
[build] copied web UI → gitnexus/web/
[build] done — rewrote 382 files.
exit=0
```

The build also emitted existing browser-externalization warnings for Node modules. They were warnings only; the build exited 0.

### Focused Swift acceptance

Command:

```text
$ npx --no-install vitest run test/unit/swift-conditional-directive-preprocess.test.ts test/integration/tree-sitter-languages.test.ts test/integration/swift-conditional-directive.test.ts test/integration/resolvers/swift.test.ts test/integration/swift-scope-capture-tripwire.test.ts test/unit/scope-resolution/swift/*.test.ts
```

Verbatim result:

```text
Test Files  8 passed (8)
     Tests  187 passed (187)
  Start at  13:57:59
  Duration  9.83s (transform 3.66s, setup 0ms, import 4.73s, tests 14.13s, environment 0ms)
```

### Real-file CLI E2E

Only a copy of `/Users/karl/src/ai-whisperer/ios/Whisp/TerminalMirrorViewModel.swift` was analyzed. The copy was placed in a temporary one-file fixture repository and indexed with an isolated `GITNEXUS_HOME`; no real repository was analyzed. Scratch was removed after the run.

Commands:

```text
GITNEXUS_HOME=<isolated-scratch-home> node dist/cli/index.js analyze --index-only --skip-git --workers 1 <copied-fixture-repo>
GITNEXUS_HOME=<isolated-scratch-home> node dist/cli/index.js cypher "MATCH (n) WHERE n.name IN ['TerminalMirrorViewModel','ConnectionType'] RETURN n.name, n.filePath, n.startLine, n.endLine ORDER BY n.startLine" -r <copied-fixture-repo>
```

Verbatim bounded output:

```text
Repository indexed successfully (8.2s)

2,242 nodes | 4,772 edges | 43 clusters | 204 flows

{
  "markdown": "| n.name | n.filePath | n.startLine | n.endLine |\n| --- | --- | --- | --- |\n| TerminalMirrorViewModel | TerminalMirrorViewModel.swift | 468 | 15537 |\n| ConnectionType | TerminalMirrorViewModel.swift | 470 | 470 |",
  "row_count": 2
}
```

### New multiline-string CLI E2E

An isolated fixture with `StringHolder.payload` containing indented `#if`/`#elseif`/`#else`/`#endif` text was analyzed. The graph read-back retained the class, property, and following method; the exported function check proved same length and byte-identical string interior, while the real directive was blanked.

Verbatim bounded output:

```text
Repository indexed successfully (4.6s)

4 nodes | 3 edges | 0 clusters | 0 flows

{
  "markdown": "| n.name | n.filePath | n.startLine | n.endLine |\n| --- | --- | --- | --- |\n| StringHolder | Fixture.swift | 0 | 10 |\n| payload | Fixture.swift | 1 | 6 |\n| afterString | Fixture.swift | 8 | 8 |",
  "row_count": 3
}
{"sameLength":true,"stringInteriorByteIdentity":true,"realDirectiveBlanked":true}
```

## Deviations and open questions

- No deviation from the requested implementation or validation scope. The build’s pre-existing web bundler warnings were non-fatal.
- A standalone `prettier --check` attempt could not run because `prettier@3.9.6` was not installed for `npx --no-install`; this was not an acceptance gate. `git diff --check` passed.
- The documented interpolation residual remains open by design; full Swift interpolation parsing is outside this light preprocessing mitigation.
- Existing same-signature conditional declarations retain the known graph deduplication tradeoff from the refutation report; this round does not change conditional-branch semantics.
- Scratch fixture repositories and isolated index homes were removed. No process required termination. The supplied untracked `REPORT-directive-refutation.md` was preserved and is not part of this implementation commit.
