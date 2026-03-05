# GitNexus Security Analysis

**Date:** 2026-03-05
**Repository:** github.com/lehenbauer/GitNexus (forked from abhigyanpatwari/GitNexus)
**Commit:** 5674b22

---

## Malware Scan: CLEAN

No malware, backdoors, data exfiltration, cryptocurrency miners, reverse shells, or credential harvesting code was found. The codebase is a legitimate code intelligence tool (knowledge graph + MCP server for AI editors).

### Details

- **No obfuscated code** — no `eval()`, `new Function()`, or encoded payload execution. One benign use of `Buffer.from().toString('base64url')` for generating short hashes (`local-backend.ts:163`).
- **No data exfiltration** — all network calls go to expected destinations (user-configured LLM APIs at openrouter.ai/openai.com, GitHub, cdn.jsdelivr.net, localhost). No code collects environment variables or system information to send externally.
- **No credential harvesting** — references to `~/.npmrc` etc. are specifically to *ignore* those files during indexing. The `setup.ts` file writes MCP configuration to editor config dirs but does not read or exfiltrate existing credentials.
- **No reverse shells** — all `child_process` usage is legitimate (`git rev-parse`, `git diff`, `rg` for text search, `node-gyp rebuild` for tree-sitter-swift). Most use `execFileSync` with array args (no shell injection possible).
- **Dependencies are legitimate** — all resolved packages in both `package-lock.json` files point to `https://registry.npmjs.org/`. No custom registries, git URL dependencies, or unusual sources. All packages are well-known (express, react, tree-sitter, kuzu, commander, etc.).
- **Install scripts are benign** — `prepare` runs `npm run build` (TypeScript compilation). `postinstall` runs `scripts/patch-tree-sitter-swift.cjs` which patches a known tree-sitter-swift build issue, well-documented with explanation of why it exists.
- **No suspicious binaries** — 14 `.wasm` files in `gitnexus-web/public/wasm/` are tree-sitter grammar parsers and KuzuDB WASM runtime (expected for browser-based code analysis).
- **No telemetry or tracking** — no analytics code in the application source.
- **No cryptocurrency miners** — no mining-related patterns found.

---

## Internet Reputation: CLEAN

No reports of GitNexus specifically containing malware, backdoors, or being disreputable were found in searches across npm security advisories, CISA alerts, and security news sites. MCP-related security news from late 2025 / early 2026 pertains to Anthropic's *official* Git MCP server (a different project), which had three CVEs (CVE-2025-68143, CVE-2025-68144, CVE-2025-68145) patched in December 2025.

---

## Security Vulnerabilities Found

### CRITICAL

#### 1. Cypher Injection in `impact()` Tool

**File:** `gitnexus/src/mcp/local/local-backend.ts:1335-1360, 1402-1425`

The `minConfidence` parameter from user input is interpolated directly into Cypher queries without parameterization:

```typescript
const confidenceFilter = minConfidence > 0 ? ` AND r.confidence >= ${minConfidence}` : '';
```

A crafted float string could inject Cypher. Additionally, `idList` and `relTypeFilter` are built via string interpolation (though `relTypeFilter` is validated against `VALID_RELATION_TYPES` and IDs come from the database with single-quote escaping).

**Recommendation:** Use `executeParameterized` with `$minConfidence` parameter. Validate that IDs contain only safe characters.

#### 2. Unvalidated Cypher in HTTP API `/api/query`

**File:** `gitnexus/src/server/api.ts:191-210`

The HTTP API accepts arbitrary Cypher queries and executes them **without write-query blocking** (unlike the MCP `cypher` tool which checks `CYPHER_WRITE_RE`). The HTTP API also opens the DB in read-write mode (unlike the MCP adapter which uses `readOnly: true`). An attacker on localhost can execute destructive Cypher operations.

**Recommendation:** Add the same `CYPHER_WRITE_RE` check, or open the DB in read-only mode.

---

### HIGH

#### 3. Dependency Vulnerabilities (11 total)

**Source:** `npm audit`

| Package | Severity | Issue |
|---------|----------|-------|
| `@hono/node-server` | HIGH | Authorization bypass via encoded slashes |
| `@isaacs/brace-expansion` | HIGH | Uncontrolled Resource Consumption |
| `@modelcontextprotocol/sdk` | HIGH | Cross-client data leak via shared server/transport reuse |
| `ajv` | MODERATE | ReDoS with `$data` option |
| `axios` | HIGH | DoS via `__proto__` key in mergeConfig |
| `hono` | HIGH | Multiple (timing comparison, cookie injection, SSE injection, arbitrary file access) |
| `minimatch` | HIGH | Multiple ReDoS patterns |
| `qs` | LOW | arrayLimit bypass |
| `tar` (via kuzu/onnxruntime-node) | HIGH | Path traversal and race conditions (no fix available) |

The `@modelcontextprotocol/sdk` vulnerability is particularly relevant since the HTTP API shares a `LocalBackend` across sessions.

**Recommendation:** Run `npm audit fix` for fixable issues.

---

### MEDIUM

#### 4. Cypher Injection via `limit` Parameter

**File:** `gitnexus/src/mcp/local/local-backend.ts:777, 798`

The `limit` parameter is interpolated directly into Cypher queries without validation:

```typescript
LIMIT ${rawLimit}
```

**Recommendation:** Add `Number.isFinite()` validation or use parameterized queries.

#### 5. Cypher Injection in `deleteNodesForFile()`

**File:** `gitnexus/src/core/kuzu/kuzu-adapter.ts:618, 630, 639, 651`

File paths are interpolated into Cypher with only single-quote escaping. KuzuDB's Cypher parser may have edge cases with backslash or Unicode that could escape the string context. Risk is lower since paths come from the filesystem during re-indexing.

**Recommendation:** Use parameterized queries.

#### 6. Cypher Injection in FTS Functions

**File:** `gitnexus/src/core/kuzu/kuzu-adapter.ts:717-718, 752-753`
**File:** `gitnexus/src/core/search/bm25-index.ts:27-32`

`tableName` and `indexName` parameters have no escaping at all before interpolation. They come from hardcoded values in the calling code, so exploitation requires modifying the caller.

**Recommendation:** Validate against a whitelist or use parameterized queries.

#### 7. Missing Input Validation on MCP Tool Parameters

**File:** `gitnexus/src/mcp/local/local-backend.ts:289`

No upper-bound validation on `maxDepth` (could cause deep graph traversal exhausting memory), `limit` (unbounded result sets), or `include_content` on large codebases.

**Recommendation:** Cap `maxDepth` at ~10, `limit` at ~1000.

---

### LOW

#### 8. Git Option Injection via `base_ref`

**File:** `gitnexus/src/mcp/local/local-backend.ts:1060-1063`

The `base_ref` parameter is passed to `execFileSync('git', ['diff', base_ref, ...])`. While shell injection is not possible with `execFileSync`, a value starting with `--` could be interpreted as a git option.

**Recommendation:** Add `--` separator before `base_ref`, or validate it doesn't start with `-`.

#### 9. Unescaped Regex in Rename Tool

**File:** `gitnexus/src/mcp/local/local-backend.ts:1260`

`oldName` is passed to ripgrep as a regex pattern without escaping metacharacters.

**Recommendation:** Use `rg --fixed-strings` or escape metacharacters for the rg call.

#### 10. API Key in Plaintext JSON

**File:** `gitnexus/src/storage/repo-manager.ts:273, 300-308`

LLM API key stored in `~/.gitnexus/config.json` as plaintext. Mitigated by `0o600` file permissions on Unix.

#### 11. No Rate Limiting on HTTP API

**Files:** `gitnexus/src/server/api.ts`, `gitnexus/src/cli/eval-server.ts`

Both servers listen on `127.0.0.1` (good) but have no rate limiting. A local process could overwhelm them with concurrent requests.

#### 12. `execSync` in `git.ts`

**File:** `gitnexus/src/storage/git.ts:8, 17, 28`

Uses `execSync` with hardcoded command strings (safe since no user input in command), but inconsistent with the `execFileSync` pattern used elsewhere.

---

## Positive Security Practices Observed

- **`execFileSync` with array args** for shell commands — prevents command injection
- **MCP database opened in read-only mode** (`kuzu-adapter.ts:164`)
- **Write-query blocking** via `CYPHER_WRITE_RE` regex on MCP Cypher tool
- **Path traversal guards** on file-serving endpoints (`api.ts:262-266`, `local-backend.ts:1172-1177`)
- **Node label whitelist** (`VALID_NODE_LABELS`) for Cypher interpolation
- **CORS restricted** to localhost and deployed site
- **Config file permissions** set to `0o600`
- **Body size limits** on HTTP servers (1MB eval, 10MB API)
- **Extensive use of `executeParameterized()`** for most queries with user-derived parameters
- **CI publishes with `--provenance`** flag for npm supply chain transparency

---

## Summary

| Category | Result |
|----------|--------|
| Malware | **CLEAN** — no malicious code found |
| Internet reputation | **CLEAN** — no adverse reports found |
| Critical vulnerabilities | **2** — Cypher injection in `impact()`, unvalidated HTTP API Cypher endpoint |
| High vulnerabilities | **1** — 11 npm dependency vulnerabilities |
| Medium vulnerabilities | **4** — Cypher interpolation issues, missing input validation |
| Low vulnerabilities | **5** — git option injection, regex escaping, plaintext API key, no rate limiting, execSync usage |

## Top Recommendations

1. Run `npm audit fix` to address dependency vulnerabilities
2. Parameterize `minConfidence` in the `impact()` tool
3. Add write-blocking to the HTTP API `/api/query` endpoint (or open DB read-only)
4. Validate and cap numeric parameters (`maxDepth`, `limit`)
5. Add `--` before `base_ref` in git diff arguments
