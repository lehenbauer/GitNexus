Result: PASS — implemented and locally committed as `e3239156` (`fix(swift): preprocess indented conditional directives so class bodies survive parsing`). No push was performed. The Swift provider now blanks only indented `#if`/`#elseif`/`#else`/`#endif` directive lines before tree-sitter parsing, preserving source length, line endings, and offsets. The six-line regression and the copied real `TerminalMirrorViewModel.swift` both retain their outer class nodes.

## Implementation summary

- Added `preprocessSwiftConditionalDirectives` in [`gitnexus/src/core/ingestion/languages/swift/conditional-directive-preprocess.ts:1-17`](gitnexus/src/core/ingestion/languages/swift/conditional-directive-preprocess.ts:1). Its multiline expression requires one or more leading spaces/tabs, matches only the four conditional directive keywords, permits conditions/trailing comments, and replaces non-newline characters with spaces.
- Registered the hook on `swiftProvider` at [`gitnexus/src/core/ingestion/languages/swift.ts:40,179-182`](gitnexus/src/core/ingestion/languages/swift.ts:40), using the existing central provider hook consumed by the parse worker at `gitnexus/src/core/ingestion/workers/parse-worker.ts:1469-1472`.
- Added direct preprocessing coverage at [`gitnexus/test/unit/swift-conditional-directive-preprocess.test.ts:4-60`](gitnexus/test/unit/swift-conditional-directive-preprocess.test.ts:4): indented directives, conditions/comments, top-level preservation, JavaScript string length, LF/CRLF newline preservation, declaration offset preservation, and directive-free identity.
- Added tree-sitter capture coverage at [`gitnexus/test/integration/tree-sitter-languages.test.ts:496-536`](gitnexus/test/integration/tree-sitter-languages.test.ts:496), covering the six-line indented fixture and a top-level conditional control fixture.
- Added a real worker-pipeline temporary-repository regression at [`gitnexus/test/integration/swift-conditional-directive.test.ts:20-40`](gitnexus/test/integration/swift-conditional-directive.test.ts:20), with one worker and forced one-file worker thresholds; it asserts `Outer`, `A`, and `B` graph nodes.

The implementation deliberately preserves every newline and every non-directive character offset. As with the root-cause report's mitigation, the parser sees declarations from all conditional branches; this can expose mutually exclusive declarations together and is a temporary grammar-workaround tradeoff.

## Red → green evidence

The red run was made before registering `preprocessSource` on `swiftProvider` (the helper and assertions were present, but the provider returned the original source). The tree-sitter test failed on the intended signal:

Command:

```text
npx --no-install vitest run test/integration/tree-sitter-languages.test.ts test/integration/swift-conditional-directive.test.ts
```

Verbatim relevant output:

```text
 FAIL  |default| test/integration/tree-sitter-languages.test.ts > Tree-sitter multi-language parsing > Swift > captures a class whose body contains indented conditional directives after preprocessing
AssertionError: expected true to be false // Object.is equality

- Expected
+ Received

- false
+ true

 ❯ test/integration/tree-sitter-languages.test.ts:511:38
    509|       const defs = extractDefinitions(matches);
    510|
    511|       expect(tree.rootNode.hasError).toBe(false);
       |                                      ^
    512|       expect(defs).toContainEqual({ type: 'definition.class', name: 'Outer' });
    513|     });
```

The same pre-build red invocation also reported the expected pipeline-test setup error because `dist/parse-worker.js` did not yet exist. After the actual build and hook registration, the pipeline assertion passed through the real worker path.

Green focused rerun after registration and build:

```text
npx --no-install vitest run test/unit/swift-conditional-directive-preprocess.test.ts test/integration/tree-sitter-languages.test.ts test/integration/swift-conditional-directive.test.ts

Test Files  3 passed (3)
Tests  55 passed (55)
```

The final focused command, including the existing Swift resolver/scope suites, passed 8 files and 182 tests; the final preprocessing unit suite passed 4 tests.

## Acceptance outputs

### Typecheck

```text
$ npx tsc --noEmit
exit=0
```

There was no typecheck diagnostic output.

### Build

```text
$ npm run build
✓ built in 287ms
[build] copied web UI → gitnexus/web/
[build] done — rewrote 382 files.
```

The build emitted the existing Vite large-chunk warning and Node 26/package-engine warnings while installing the absent web dependencies; the command exited 0. The CLI used for E2E was the resulting `node dist/cli/index.js`.

### New tests plus existing Swift ingestion/scope tests

Command:

```text
npx --no-install vitest run test/unit/swift-conditional-directive-preprocess.test.ts test/integration/tree-sitter-languages.test.ts test/integration/swift-conditional-directive.test.ts test/integration/resolvers/swift.test.ts test/integration/swift-scope-capture-tripwire.test.ts test/unit/scope-resolution/swift/*.test.ts
```

Verbatim result:

```text
Test Files  8 passed (8)
Tests  182 passed (182)
Start at  13:30:31
Duration  10.04s (transform 3.74s, setup 0ms, import 4.89s, tests 14.15s, environment 1ms)
```

The broader `rg -l -i 'swift' test -g '*test.ts'` sweep covered 56 matching test files. It produced 55 passing files, 2,737 passing tests, and one skipped test, with two failures in the pre-existing `test/unit/call-summary-schema-version.test.ts` assertions at lines 81 and 209: those assertions expect schema version `30`, while this base reports `31`. No Swift-related failure occurred in the focused command above. This unrelated base mismatch was not changed.

### Real-file CLI E2E

Only a copied fixture was analyzed. The source was copied from `/Users/karl/src/ai-whisperer/ios/Whisp/TerminalMirrorViewModel.swift` into a temporary one-file repository. The index home was an isolated temporary `GITNEXUS_HOME`; no analysis was run against the Whisp checkout, GitNexus checkout, or any worktree.

Command shape:

```text
GITNEXUS_HOME=<isolated-scratch-home> node dist/cli/index.js analyze --index-only --skip-git --workers 1 <copied-fixture-repo>
GITNEXUS_HOME=<isolated-scratch-home> node dist/cli/index.js cypher "MATCH (n) WHERE n.name IN ['TerminalMirrorViewModel','ConnectionType'] RETURN n.name, n.filePath, n.startLine, n.endLine ORDER BY n.startLine" -r <copied-fixture-repo>
```

Verbatim bounded output:

```text
Repository indexed successfully (8.5s)

2,242 nodes | 4,772 edges | 43 clusters | 204 flows

{
  "markdown": "| n.name | n.filePath | n.startLine | n.endLine |\n| --- | --- | --- | --- |\n| TerminalMirrorViewModel | TerminalMirrorViewModel.swift | 468 | 15537 |\n| ConnectionType | TerminalMirrorViewModel.swift | 470 | 470 |",
  "row_count": 2
}
```

`TerminalMirrorViewModel` is present with plausible 0-based graph lines `468..15537`; `ConnectionType` remains present at `470..470`.

### No-directive control fixture

The control source was a small class with a property and method and no conditional directives. The unit identity assertion proves the hook returns this source byte-for-byte unchanged. A separate isolated CLI fixture produced:

```text
Repository indexed successfully (4.5s)

4 nodes | 3 edges | 0 clusters | 0 flows

{
  "markdown": "| node_count |\n| --- |\n| 4 |",
  "row_count": 1
}
{
  "markdown": "| n.name | n.startLine | n.endLine |\n| --- | --- | --- |\n| Plain | 0 | 3 |\n| value | 1 | 1 |\n| read | 2 | 2 |",
  "row_count": 3
}
```

Because the preprocessor is an identity function for this source (covered directly by the unit test), the control graph is unchanged by the hook by construction; the CLI read-back confirms the expected class/property/method structure and lines.

## Deviations and open questions

- The root-cause report showed the helper inline in `swift.ts`. I placed it in `languages/swift/conditional-directive-preprocess.ts` and imported it from `swift.ts` instead. This follows the local Dart `extension-type-preprocess.ts` precedent and makes the preprocessing function directly unit-testable without exposing unrelated provider internals.
- The automated pipeline regression uses `runPipelineFromRepo` with the production worker pool and one worker. The required real CLI build/E2E proof is separately executed above with `node dist/cli/index.js`, isolated `GITNEXUS_HOME`, and copied fixtures.
- The regex uses an explicit `(?=\r?$)` line-ending lookahead rather than relying on `$` to consume a CRLF boundary. This makes the CRLF safety contract explicit while preserving `\r\n` unchanged.
- The full grep-selected Swift-text sweep retained two unrelated CALL_SUMMARY schema-version failures described above; no unrelated source or tests were modified. The all-test `npm test` command was not used as a release gate because the repository already has that independent base mismatch; the requested focused Swift gates were green.
- The long-term grammar fix remains open as described in the root-cause report. This mitigation intentionally trades conditional-branch semantic fidelity for preserving the enclosing declaration under tree-sitter-swift 0.7.1.
- GitNexus impact/detect tooling could only use the canonical checkout's stale graph (664 commits behind); it reported low risk and no affected processes but was not treated as current proof. The task's strict limit prohibited refreshing/analyzing real repositories, so source inspection and the focused tests are the authoritative evidence.
- Scratch fixture repositories and isolated index homes were removed after validation. No process was started that required termination. The worktree was left with only the committed implementation and this report as the requested durable record.
