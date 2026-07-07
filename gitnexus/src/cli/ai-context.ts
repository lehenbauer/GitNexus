/**
 * AI Context Generator
 *
 * Creates AGENTS.md with inline GitNexus context and CLAUDE.md with an @AGENTS.md import stub.
 * AGENTS.md is the standard read by Cursor, Windsurf, OpenCode, Codex, Cline, etc.
 * CLAUDE.md is for Claude Code, which resolves the @AGENTS.md import.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { type GeneratedSkillInfo } from './skill-gen.js';
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
 * Design principles:
 * - Keep the default block under ~20 lines so it is cheap to read every turn
 * - Put usage rules in AGENTS.md once; CLAUDE.md imports them instead of duplicating
 * - Scope mandates to structural questions and load-bearing edits, and carve out
 *   cosmetic or single-file work where GitNexus will not change the plan
 * - Include an explicit budget rule: one answer-producing query beats repeated checks
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

function generateGitNexusContent(
  projectName: string,
  stats: RepoStats,
  generatedSkills?: GeneratedSkillInfo[],
  groupNames?: string[],
  noStats?: boolean,
  skipSkills?: boolean,
): string {
  const generatedRows =
    generatedSkills && generatedSkills.length > 0
      ? generatedSkills
          .map(
            (s) =>
              `| Work in the ${s.label} area (${s.symbolCount} symbols) | \`.claude/skills/generated/${s.name}/SKILL.md\` |`,
          )
          .join('\n')
      : '';

  const skillsTable = generatedRows
    ? `| Task | Read this skill file |
|------|---------------------|
${generatedRows}`
    : '';

  return `${GITNEXUS_START_MARKER}
## GitNexus — Code Intelligence

This repo is indexed by GitNexus as **${projectName}**. The GitNexus MCP tools answer questions from the call graph — faster and more reliable than grep when the answer spans files.

Reach for it when the question is structural:

- Trace a flow / "how does X work" → \`gitnexus_query({query: "concept"})\`
- Blast radius before editing an exported or widely-called symbol → \`gitnexus_impact({target: "symbolName", direction: "upstream"})\`. Mention HIGH/CRITICAL findings to the user before proceeding — never silently.
- Renames → \`gitnexus_rename\`, never repo-wide find-and-replace.

Skip it when it won't change what you do: locating a known string or file (grep/Read is fine), cosmetic or single-file edits, docs/copy. One query that answers the question beats three that confirm it — stop when you have the answer.

If a tool warns the index is stale, run \`npx gitnexus analyze\` first.

${
  groupNames && groupNames.length > 0
    ? `## Cross-Repo Groups

This repository is listed under GitNexus **group(s): ${groupNames.join(', ')}** (see \`~/.gitnexus/groups/\`). For cross-repo analysis, use MCP tools \`impact\`, \`query\`, and \`context\` with \`repo\` set to \`@<groupName>\` or \`@<groupName>/<memberPath>\` (paths match keys in that group’s \`group.yaml\`). Use \`group_list\` / \`group_sync\` for membership and sync. From the terminal: \`npx gitnexus group list\`, \`npx gitnexus group sync <name>\`, \`npx gitnexus group impact <name> --target <symbol> --repo <group-path>\`.

`
    : ''
}${
    !skipSkills
      ? `Deeper guides (exploring, impact analysis, debugging, refactoring, tools reference, CLI): \`.claude/skills/gitnexus/\`.

`
      : ''
  }${
    skillsTable
      ? `${skillsTable}

`
      : ''
  }${GITNEXUS_END_MARKER}`;
}

function generateClaudeAgentsImportStub(projectName: string): string {
  return `${GITNEXUS_START_MARKER}
## GitNexus — Code Intelligence

This repo is indexed by GitNexus as **${projectName}**. The GitNexus usage rules live in the gitnexus block of AGENTS.md, imported here: @AGENTS.md
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
      // Volatile counts are never emitted: they churn commits without adding
      // value (a stale count is still wrong). The project name still refreshes
      // so renames propagate. The optional parenthetical in statsPattern below
      // lets us pick up any legacy line that still carries counts.
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

    // No keep marker — replace existing section with full verbose content
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
 * Install GitNexus skills to .claude/skills/gitnexus/
 * Works natively with Claude Code, Cursor, and GitHub Copilot
 */
async function installSkills(repoPath: string): Promise<string[]> {
  const skillsDir = path.join(repoPath, '.claude', 'skills', 'gitnexus');
  const installedSkills: string[] = [];

  // Skill definitions bundled with the package
  const skills = [
    {
      name: 'gitnexus-exploring',
      description:
        'Use when the user asks how code works, wants to understand architecture, trace execution flows, or explore unfamiliar parts of the codebase. Examples: "How does X work?", "What calls this function?", "Show me the auth flow"',
    },
    {
      name: 'gitnexus-debugging',
      description:
        'Use when the user is debugging a bug, tracing an error, or asking why something fails. Examples: "Why is X failing?", "Where does this error come from?", "Trace this bug"',
    },
    {
      name: 'gitnexus-impact-analysis',
      description:
        'Use when the user wants to know what will break if they change something, or needs safety analysis before editing code. Examples: "Is it safe to change X?", "What depends on this?", "What will break?"',
    },
    {
      name: 'gitnexus-refactoring',
      description:
        'Use when the user wants to rename, extract, split, move, or restructure code safely. Examples: "Rename this function", "Extract this into a module", "Refactor this class", "Move this to a separate file"',
    },
    {
      name: 'gitnexus-guide',
      description:
        'Use when the user asks about GitNexus itself — available tools, how to query the knowledge graph, MCP resources, graph schema, or workflow reference. Examples: "What GitNexus tools are available?", "How do I use GitNexus?"',
    },
    {
      name: 'gitnexus-cli',
      description:
        'Use when the user needs to run GitNexus CLI commands like analyze/index a repo, check status, clean the index, generate a wiki, or list indexed repos. Examples: "Index this repo", "Reanalyze the codebase", "Generate a wiki"',
    },
  ];

  for (const skill of skills) {
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
description: ${skill.description}
---

# ${skill.name.charAt(0).toUpperCase() + skill.name.slice(1)}

${skill.description}

Use GitNexus tools to accomplish this task.
`;
      }

      await fs.writeFile(skillPath, skillContent, 'utf-8');
      installedSkills.push(skill.name);
    } catch (err) {
      // Skip on error, don't fail the whole process
      logger.warn({ err }, `Warning: Could not install skill ${skill.name}:`);
    }
  }

  return installedSkills;
}

/**
 * Generate AI context files after indexing
 */
export async function generateAIContextFiles(
  repoPath: string,
  _storagePath: string,
  projectName: string,
  stats: RepoStats,
  generatedSkills?: GeneratedSkillInfo[],
  options?: AIContextOptions,
): Promise<{ files: string[] }> {
  const groupNames = await findGroupsContainingRegistryName(projectName);
  const agentsContent = generateGitNexusContent(
    projectName,
    stats,
    generatedSkills,
    groupNames,
    options?.noStats,
    options?.skipSkills,
  );
  const claudeContent = generateClaudeAgentsImportStub(projectName);
  const createdFiles: string[] = [];

  if (!options?.skipAgentsMd) {
    // Create AGENTS.md (standard for Cursor, Windsurf, OpenCode, Cline, etc.)
    const agentsPath = path.join(repoPath, 'AGENTS.md');
    const agentsResult = await upsertGitNexusSection(
      agentsPath,
      agentsContent,
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

  // Install skills to .claude/skills/gitnexus/ (unless --skip-skills)
  if (!options?.skipSkills) {
    const installedSkills = await installSkills(repoPath);
    if (installedSkills.length > 0) {
      createdFiles.push(`.claude/skills/gitnexus/ (${installedSkills.length} skills)`);
    }
  } else {
    createdFiles.push('.claude/skills/gitnexus/ (skipped via --skip-skills)');
  }

  return { files: createdFiles };
}
