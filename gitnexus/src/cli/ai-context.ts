/**
 * AI Context Generator
 *
 * Creates AGENTS.md and CLAUDE.md with full inline GitNexus context.
 * AGENTS.md is the standard read by Cursor, Windsurf, OpenCode, Codex, Cline, CodeBuddy, Qoder, etc.
 * CLAUDE.md is for Claude Code which only reads that file.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { type GeneratedSkillInfo } from './skill-gen.js';
import { STANDARD_SKILL_CATALOG } from './standard-skills.js';
import { logger } from '../core/logger.js';

// ESM equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface RepoStats {
  files?: number;
  nodes?: number;
  edges?: number;
  communities?: number;
  clusters?: number; // Aggregated cluster count (what tools show)
  processes?: number;
}

export interface AIContextOptions {
  skipAgentsMd?: boolean;
  noStats?: boolean;
  skipSkills?: boolean;
  /**
   * Default branch used by the generated regression-compare example (#243).
   * Resolved by the CLI (CLI flag > `.gitnexusrc` > auto-detect > "main"); a
   * plain caller that omits it gets "main", preserving prior behavior.
   */
  defaultBranch?: string;
  /**
   * Whether the index was built with `--pdg` (#2086 M6). Gates the `pdg_query`
   * line in the generated block — without the PDG layer the tool only returns a
   * "no PDG layer" note, so advertising it on a non-`--pdg` index is noise.
   */
  hasPdg?: boolean;
}

const GITNEXUS_START_MARKER = '<!-- gitnexus:start -->';
const GITNEXUS_END_MARKER = '<!-- gitnexus:end -->';

/**
 * Find the index of a section marker that occupies its own line.
 * Unlike `indexOf`, this rejects inline prose references like
 * `` See the `<!-- gitnexus:start -->` block `` that appear
 * mid-sentence (#1041). A marker counts as section-position only when:
 *   - preceded by newline or start-of-file, AND
 *   - followed by newline, `\r` (CRLF files), or end-of-file.
 * The generator always emits each marker alone on its line, so this
 * matches every legitimate section and none of the inline mentions.
 *
 * `startFrom` lets the end-marker lookup start after the already-found
 * start marker, avoiding a scan from 0 and guaranteeing we never pick
 * up an end marker that appears earlier in the file than the start.
 */
function findSectionMarkerIndex(content: string, marker: string, startFrom = 0): number {
  let idx = content.indexOf(marker, startFrom);
  while (idx !== -1) {
    const atLineStart = idx === 0 || content[idx - 1] === '\n';
    const endPos = idx + marker.length;
    const atLineEnd =
      endPos === content.length || content[endPos] === '\n' || content[endPos] === '\r';
    if (atLineStart && atLineEnd) return idx;
    idx = content.indexOf(marker, idx + 1);
  }
  return -1;
}

/**
 * Generate the full GitNexus context content.
 *
 * Keep this block opt-in and short: graph tools are useful when multi-file
 * structure is the bottleneck, but should not gate local or cosmetic edits.
 */
async function findGroupsContainingRegistryName(registryName: string): Promise<string[]> {
  const { listGroups, getDefaultGitnexusDir, getGroupDir } =
    await import('../core/group/storage.js');
  const { loadGroupConfig } = await import('../core/group/config-parser.js');
  const names = await listGroups();
  const hits: string[] = [];
  for (const g of names) {
    try {
      const config = await loadGroupConfig(getGroupDir(getDefaultGitnexusDir(), g));
      if (Object.values(config.repos).some((r) => r === registryName)) hits.push(config.name);
    } catch {
      // skip invalid or unreadable groups
    }
  }
  return hits;
}

/**
 * Strip backticks from a branch name before it is embedded in a Markdown
 * inline-code span (#1996 tri-review P1). validateBranchName already rejects
 * backticks for CLI/config/auto-detect inputs; this is the last-line defense at
 * the generation sink so the embedding is provably safe regardless of caller.
 */
export function markdownSafeBranch(branch: string): string {
  return branch.replace(/`/g, '');
}

/** Options for {@link generateGitNexusContent} (collapsed from positional
 *  params, #2188 review — six `undefined`s to reach `hasPdg` was the smell). */
export interface GitNexusContentOptions {
  generatedSkills?: GeneratedSkillInfo[];
  groupNames?: string[];
  noStats?: boolean;
  skipSkills?: boolean;
  /** Project-relative path to the runner `gitnexus analyze` drops next to the
   *  index (#1945). Referenced by docs so a single CLI-neutral command resolves
   *  the available runner (global `gitnexus` → `pnpm dlx` → `npx`) at call time. */
  runnerPath?: string;
  /** Default branch for the regression-compare example (#243). Configurable so
   *  projects on `develop`/`master`/etc. don't get `base_ref: "main"` rewritten
   *  back over their fix on every analyze. The value is embedded inside a
   *  Markdown inline-code span: validateBranchName rejects backticks upstream,
   *  and `markdownSafeBranch` strips any remaining backtick here as defense in
   *  depth, so JSON.stringify's quote/escape handling is sufficient and the
   *  branch cannot break out of the span (#1996 tri-review P1). */
  defaultBranch?: string;
  /** Whether the index was built with `--pdg` (#2086 M6). Gates the pdg_query
   *  line below — false (default) omits it, so a non-pdg index doesn't advertise
   *  a tool that only returns a "no PDG layer" note. */
  hasPdg?: boolean;
}

export function generateGitNexusContent(
  projectName: string,
  stats: RepoStats,
  opts: GitNexusContentOptions = {},
): string {
  const {
    generatedSkills,
    groupNames,
    noStats,
    skipSkills,
    runnerPath = '.gitnexus/run.cjs',
    defaultBranch = 'main',
    hasPdg = false,
  } = opts;
  const generatedRows =
    generatedSkills && generatedSkills.length > 0
      ? generatedSkills
          .map(
            (s) =>
              `| Work in the ${s.label} area (${s.symbolCount} symbols) | \`.claude/skills/${s.name}/SKILL.md\` |`,
          )
          .join('\n')
      : '';

  // Standard skill rows reference files installed by installSkills(). When
  // --skip-skills suppresses that install, these rows must be omitted — else
  // AGENTS.md/CLAUDE.md would direct agents to read files that don't exist.
  // Community skills (generatedRows) live directly under .claude/skills/ and
  // are independent of --skip-skills, so they remain when present.
  const standardSkillsRows = skipSkills
    ? ''
    : STANDARD_SKILL_CATALOG.filter((skill) => skill.distributions.project)
        .map((skill) => `| ${skill.agentTableTask} | \`.claude/skills/${skill.name}/SKILL.md\` |`)
        .join('\n');

  const tableBody = [standardSkillsRows, generatedRows].filter(Boolean).join('\n');
  const skillsTable = tableBody
    ? `| Task | Read this skill file |
| --- | --- |
${tableBody}`
    : '';
  // Docs reference the project-local runner `gitnexus analyze` writes (#1945):
  // a single, CLI-neutral, machine-independent command (no per-machine churn,
  // #1706) that auto-selects the available runner at call time. Kept terse to
  // stay under the CLAUDE.md block token budget (#856); the cli skill carries the
  // full bootstrap + npm-11 fallback (`node.target is null` npx install crash).
  const runner = `node ${runnerPath}`;
  const bootstrapNote =
    `No \`${runnerPath}\` yet? \`npx gitnexus analyze\` ` +
    '(npm 11 crash → `npm i -g gitnexus`; #1939).';

  return `${GITNEXUS_START_MARKER}
# GitNexus — Code Intelligence

This repo is indexed as **${projectName}**. Optional MCP tools over the call/import graph — not a default step for every edit.

**Useful when** the hard part is multi-file structure a single grep or file read will not show:
- Who calls / depends on a symbol across modules → \`gitnexus_impact\` / \`gitnexus_context\`
- How a concept is wired end-to-end → \`gitnexus_query\`
- Multi-file rename of a symbol with many graph refs → \`gitnexus_rename\`

**Skip for** local or non-graph work: known path or string, single-file edits, HTML/CSS/markup, copy, configs, fixtures, generated files, tests you already have open. Prefer normal editor tools there. One graph query that answers the question is enough — do not chain impact/context by habit.

If a tool says the index is stale, run \`${runner} analyze\` from the project root. Otherwise ignore staleness. ${bootstrapNote}

**Worktrees:** queries work from any checkout. To graph a linked worktree's branch, run \`npx gitnexus analyze --index-only --name ${projectName}-<branch>\` from the worktree root — its index lives in that worktree's own \`.gitnexus/\`, separate from this one. \`npx gitnexus remove <worktree-path> --force\` cleans it up when the branch work ends.

**Optional regression review:** compare affected scope with \`detect_changes({scope: "compare", base_ref: ${JSON.stringify(markdownSafeBranch(defaultBranch))}})\` when a multi-file review needs it.${
    hasPdg
      ? `\n\n**Optional PDG analysis:** \`pdg_query\` answers "under what condition does X run?" with \`mode: "controls"\` and can trace data flow with \`mode: "flows"\`; use \`line: <N>\`, \`affectedStatements\`, and \`byDepth\` when this index was built with \`--pdg\`.`
      : ''
  }

${
  groupNames && groupNames.length > 0
    ? `## Cross-Repo Groups

This repository is listed under GitNexus **group(s): ${groupNames.join(', ')}** (see \`~/.gitnexus/groups/\`). For cross-repo analysis, use MCP tools \`impact\`, \`query\`, and \`context\` with \`repo\` set to \`@<groupName>\` or \`@<groupName>/<memberPath>\` (paths match keys in that group’s \`group.yaml\`). Use \`group_list\` / \`group_sync\` for membership and sync. From the project root: \`${runner} group list\`, \`${runner} group sync <name>\`, \`${runner} group impact <name> --target <symbol> --repo <group-path>\` (the \`${runnerPath}\` path is repo-root-relative).

`
    : ''
}${
    skillsTable
      ? `## CLI

${skillsTable}

`
      : ''
  }${GITNEXUS_END_MARKER}`;
}

function generateClaudeAgentsImportStub(projectName: string): string {
  return `${GITNEXUS_START_MARKER}
## GitNexus — Code Intelligence

This repo is indexed as **${projectName}**. Optional graph tools; usage guidance lives in the gitnexus block of AGENTS.md, imported here: @AGENTS.md
${GITNEXUS_END_MARKER}`;
}

/**
 * Check if a file exists
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Create or update GitNexus section in a file
 * - If file doesn't exist: create with GitNexus content
 * - If file exists without GitNexus section: append
 * - If file exists with GitNexus section: replace that section
 */
async function upsertGitNexusSection(
  filePath: string,
  content: string,
  projectName: string,
  stats: RepoStats,
  noStats?: boolean,
): Promise<'created' | 'updated' | 'appended' | 'preserved'> {
  const exists = await fileExists(filePath);

  if (!exists) {
    await fs.writeFile(filePath, content, 'utf-8');
    return 'created';
  }

  const existingContent = await fs.readFile(filePath, 'utf-8');

  // Check if GitNexus section already exists. Matching is restricted
  // to markers that occupy their own line so that inline prose
  // references (e.g. `` See the `<!-- gitnexus:start -->` block `` in
  // the shipped CLAUDE.md) are NOT treated as section delimiters
  // (#1041). The end-marker scan starts after the start-marker so it
  // can never pick up an earlier end in the file.
  const startIdx = findSectionMarkerIndex(existingContent, GITNEXUS_START_MARKER);
  const endIdx = findSectionMarkerIndex(
    existingContent,
    GITNEXUS_END_MARKER,
    startIdx === -1 ? 0 : startIdx,
  );

  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    const existingSection = existingContent.substring(
      startIdx,
      endIdx + GITNEXUS_END_MARKER.length,
    );

    // If the existing section contains <!-- gitnexus:keep -->, preserve the user's
    // custom layout and only update the stats line (node/edge/flow counts).
    // This lets teams trim the verbose default template to a lean format without
    // having it overwritten on every `gitnexus analyze`.
    //
    // Note: the keep-marker check operates on `existingSection` (the substring
    // between valid section markers identified by findSectionMarkerIndex), so
    // a keep marker in user prose OUTSIDE the GitNexus block has no effect.
    if (existingSection.includes('<!-- gitnexus:keep -->')) {
      // Volatile counts are never emitted in this fork: they churn commits
      // without adding value, and a stale count is still wrong.
      const statsLine = `Indexed as **${projectName}**`;

      // Match either canonical phrasing at line start (`^` with `m` flag) so we
      // cannot replace prose embedded mid-paragraph. Deliberately no `$`: text
      // after the line on the same line (e.g. ". MCP tools.") stays intact.
      // The parenthetical is optional so a count-free line left by a prior
      // --no-stats run still matches — letting the name refresh, and letting
      // counts return if --no-stats is later dropped.
      const statsPattern = /^(?:Indexed as|indexed by GitNexus as) \*\*[^*]+\*\*(?: \([^)]+\))?/m;

      if (statsPattern.test(existingSection)) {
        const updatedSection = existingSection.replace(statsPattern, statsLine);
        const before = existingContent.substring(0, startIdx);
        const after = existingContent.substring(endIdx + GITNEXUS_END_MARKER.length);
        await fs.writeFile(filePath, (before + updatedSection + after).trim() + '\n', 'utf-8');
        return 'updated';
      }
      // Keep marker present but no stats line matched. Section is preserved
      // unchanged on disk; return a distinct status so callers/CLI output
      // don't mis-report this as 'updated' (which would imply a write).
      return 'preserved';
    }

    // No keep marker — replace existing section with the concise content
    const before = existingContent.substring(0, startIdx);
    const after = existingContent.substring(endIdx + GITNEXUS_END_MARKER.length);
    const newContent = before + content + after;
    await fs.writeFile(filePath, newContent.trim() + '\n', 'utf-8');
    return 'updated';
  }

  // Append new section
  const newContent = existingContent.trim() + '\n\n' + content + '\n';
  await fs.writeFile(filePath, newContent, 'utf-8');
  return 'appended';
}

/**
 * Some agents read skills from a repo-local `.agents/skills/` directory and
 * prefer it over the global `~/.agents/skills/` install. When the repo contains
 * an `.agents/` directory, skills written to `.claude/skills/` are mirrored
 * there too so those agents serve the up-to-date copies.
 */
export async function shouldMirrorSkillsToAgents(repoPath: string): Promise<boolean> {
  try {
    const stat = await fs.stat(path.join(repoPath, '.agents'));
    return stat.isDirectory();
  } catch {
    return false;
  }
}

/**
 * Install GitNexus skills as direct children of .claude/skills/
 * Works natively with Claude Code, Cursor, and GitHub Copilot.
 * Mirrored to .agents/skills/ when .agents/ exists.
 */
async function installSkills(
  repoPath: string,
): Promise<{ skills: string[]; agentsMirror: boolean }> {
  const skillsDir = path.join(repoPath, '.claude', 'skills');
  const legacySkillsDir = path.join(skillsDir, 'gitnexus');
  const installedSkills: string[] = [];
  const agentsMirror = await shouldMirrorSkillsToAgents(repoPath);

  for (const skill of STANDARD_SKILL_CATALOG.filter(
    (entry) => entry.distributions.project && entry.distributions.npm,
  )) {
    const skillDir = path.join(skillsDir, skill.name);
    const skillPath = path.join(skillDir, 'SKILL.md');

    try {
      // Create skill directory
      await fs.mkdir(skillDir, { recursive: true });

      // Try to read from package skills directory
      const packageSkillPath = path.join(__dirname, '..', '..', 'skills', `${skill.name}.md`);
      let skillContent: string;

      try {
        skillContent = await fs.readFile(packageSkillPath, 'utf-8');
      } catch {
        // Fallback: generate minimal skill content
        skillContent = `---
name: ${skill.name}
description: ${skill.fallbackDescription}
---

# ${skill.name.charAt(0).toUpperCase() + skill.name.slice(1)}

${skill.fallbackDescription}

Use GitNexus tools to accomplish this task.
`;
      }

      await fs.writeFile(skillPath, skillContent, 'utf-8');

      // Mirror to .agents/skills/ for agents that read repo-local skills
      if (agentsMirror) {
        try {
          const agentsSkillDir = path.join(repoPath, '.agents', 'skills', skill.name);
          await fs.mkdir(agentsSkillDir, { recursive: true });
          await fs.writeFile(path.join(agentsSkillDir, 'SKILL.md'), skillContent, 'utf-8');
        } catch (err) {
          logger.warn({ err }, `Warning: Could not mirror skill ${skill.name} to .agents/skills:`);
        }
      }

      installedSkills.push(skill.name);

      // Previous releases installed these known standard skills one level too
      // deep. Remove only the child owned by this installer; unknown siblings
      // under the legacy grouping directory may be user-authored and survive.
      try {
        await fs.rm(path.join(legacySkillsDir, skill.name), { recursive: true, force: true });
      } catch (err) {
        logger.warn({ err }, `Warning: Could not remove legacy skill ${skill.name}:`);
      }
    } catch (err) {
      // Skip on error, don't fail the whole process
      logger.warn({ err }, `Warning: Could not install skill ${skill.name}:`);
    }
  }

  return { skills: installedSkills, agentsMirror };
}

/**
 * Generate AI context files after indexing
 */
export async function generateAIContextFiles(
  repoPath: string,
  storagePath: string,
  projectName: string,
  stats: RepoStats,
  generatedSkills?: GeneratedSkillInfo[],
  options?: AIContextOptions,
): Promise<{ files: string[] }> {
  const groupNames = await findGroupsContainingRegistryName(projectName);

  // Drop a project-local runner next to the index (#1945) so the generated docs
  // can reference one CLI-neutral command that resolves the available runner at
  // call time. It is a copy of the canonical self-contained resolver, which the
  // CLI and hooks already share; failure to copy is non-fatal (docs carry a
  // bootstrap fallback). `runnerPath` is project-relative with POSIX separators
  // so the emitted command is identical across platforms.
  const runnerPath = path.relative(repoPath, path.join(storagePath, 'run.cjs')).replace(/\\/g, '/');
  try {
    const runnerSrc = path.join(
      __dirname,
      '..',
      '..',
      'hooks',
      'claude',
      'resolve-analyze-cmd.cjs',
    );
    await fs.mkdir(storagePath, { recursive: true });
    await fs.copyFile(runnerSrc, path.join(storagePath, 'run.cjs'));
  } catch (err) {
    logger.warn(`Could not write GitNexus runner to ${runnerPath}: ${String(err)}`);
  }

  const content = generateGitNexusContent(projectName, stats, {
    generatedSkills,
    groupNames,
    noStats: options?.noStats,
    skipSkills: options?.skipSkills,
    runnerPath,
    defaultBranch: options?.defaultBranch ?? 'main',
    hasPdg: options?.hasPdg ?? false,
  });
  const claudeContent = generateClaudeAgentsImportStub(projectName);
  const createdFiles: string[] = [];

  if (!options?.skipAgentsMd) {
    // Create AGENTS.md (standard for Cursor, Windsurf, OpenCode, Cline, etc.)
    const agentsPath = path.join(repoPath, 'AGENTS.md');
    const agentsResult = await upsertGitNexusSection(
      agentsPath,
      content,
      projectName,
      stats,
      options?.noStats,
    );
    createdFiles.push(`AGENTS.md (${agentsResult})`);

    // Create CLAUDE.md (for Claude Code)
    const claudePath = path.join(repoPath, 'CLAUDE.md');
    const claudeResult = await upsertGitNexusSection(
      claudePath,
      claudeContent,
      projectName,
      stats,
      options?.noStats,
    );
    createdFiles.push(`CLAUDE.md (${claudeResult})`);
  } else {
    createdFiles.push('AGENTS.md (skipped via --skip-agents-md)');
    createdFiles.push('CLAUDE.md (skipped via --skip-agents-md)');
  }

  // Install standard skills directly under .claude/skills/ (unless --skip-skills)
  if (!options?.skipSkills) {
    const { skills: installedSkills, agentsMirror } = await installSkills(repoPath);
    if (installedSkills.length > 0) {
      createdFiles.push(`.claude/skills/gitnexus-*/ (${installedSkills.length} skills)`);
      if (agentsMirror) {
        createdFiles.push(
          `.agents/skills/gitnexus-*/ (${installedSkills.length} skills mirrored for .agents)`,
        );
      }
    }
  } else {
    createdFiles.push('.claude/skills/gitnexus-*/ (skipped via --skip-skills)');
  }

  return { files: createdFiles };
}

/**
 * Refresh only the `base_ref: "..."` value inside the GitNexus block of an
 * already-generated AGENTS.md / CLAUDE.md, in place (#1996 tri-review P2).
 *
 * The `alreadyUpToDate` analyze fast path returns before the normal
 * {@link generateAIContextFiles} call, so a changed `.gitnexusrc` defaultBranch
 * (or `--default-branch`) would otherwise not take effect until the next
 * re-index. This does a surgical line update that preserves the rest of the
 * block — including community-skill rows written by a prior `--skills` run —
 * rather than regenerating (which would drop those rows on a no-`--skills` run).
 *
 * Best-effort: missing files, a missing/blank block, or a block with no
 * `base_ref` line (e.g. a user-trimmed keep block) are silently skipped. Writes
 * only when the value actually changes, so a routine up-to-date run is a no-op.
 */
export async function refreshBaseRefLine(
  repoPath: string,
  defaultBranch: string,
  options?: { skipAgentsMd?: boolean },
): Promise<{ files: string[] }> {
  if (options?.skipAgentsMd) return { files: [] };
  const replacement = `base_ref: ${JSON.stringify(markdownSafeBranch(defaultBranch))}`;
  const updated: string[] = [];
  for (const name of ['AGENTS.md', 'CLAUDE.md']) {
    const filePath = path.join(repoPath, name);
    if (!(await fileExists(filePath))) continue;
    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue;
    }
    const startIdx = findSectionMarkerIndex(content, GITNEXUS_START_MARKER);
    if (startIdx === -1) continue;
    const endIdx = findSectionMarkerIndex(content, GITNEXUS_END_MARKER, startIdx);
    if (endIdx === -1 || endIdx <= startIdx) continue;
    const blockEnd = endIdx + GITNEXUS_END_MARKER.length;
    const block = content.substring(startIdx, blockEnd);
    // Only the generated regression example carries a base_ref line, and only
    // one per block; replace its quoted value while leaving the rest untouched.
    const newBlock = block.replace(/base_ref: "(?:[^"\\]|\\.)*"/, replacement);
    if (newBlock === block) continue; // no base_ref line present, or already current
    const newContent = content.substring(0, startIdx) + newBlock + content.substring(blockEnd);
    try {
      await fs.writeFile(filePath, newContent, 'utf-8');
      updated.push(name);
    } catch {
      // best-effort — never fail analyze over a context refresh
    }
  }
  return { files: updated };
}
