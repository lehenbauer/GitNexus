/**
 * MCP Server (Multi-Repo)
 *
 * Model Context Protocol server that runs on stdio.
 * External AI tools (Cursor, Claude) spawn this process and
 * communicate via stdin/stdout using the MCP protocol.
 *
 * Supports multiple indexed repositories via the global registry.
 *
 * Tools: list_repos, query, cypher, context, impact, detect_changes, rename
 * Resources: repos, repo/{name}/context, repo/{name}/clusters, ...
 */

import { createRequire } from 'module';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CompatibleStdioServerTransport } from './compatible-stdio-transport.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { GITNEXUS_TOOLS } from './tools.js';
import { installGlobalStdoutSentinel } from './stdio-context.js';
import type { LocalBackend } from './local/local-backend.js';
import { getResourceDefinitions, getResourceTemplates, readResource } from './resources.js';

/**
 * Optional follow-ups appended to tool responses.
 *
 * Keep these soft: hard "Next: always run X" chains cause cargo-cult tool
 * use (impact after every context, etc.). Only hint when a deeper graph
 * step is genuinely optional and useful — never a pre-edit gate.
 */
function getNextStepHint(toolName: string, args: Record<string, any> | undefined): string {
  const repo = args?.repo;
  const repoParam = repo ? `, repo: "${repo}"` : '';
  const repoPath = repo || '{name}';

  switch (toolName) {
    case 'list_repos':
      return `\n\n---\n**Optional:** READ gitnexus://repo/{name}/context if you need an overview or staleness check.`;

    case 'query':
      return `\n\n---\n**Optional:** context({name: "<symbol>"${repoParam}}) only if you need callers/callees for a specific symbol above.`;

    case 'context':
      return `\n\n---\n**Optional:** impact({target: "${args?.name || '<name>'}", direction: "upstream"${repoParam}}) only if you need a multi-file dependency map before a risky change — skip for local/single-file edits.`;

    case 'impact':
      return `\n\n---\n**Optional:** Focus on d=1 (WILL BREAK) if any; otherwise proceed from what you already have.`;

    case 'detect_changes':
      return `\n\n---\n**Optional:** context() on a high-risk changed symbol only if scope is still unclear.`;

    case 'rename':
      return `\n\n---\n**Optional:** detect_changes(${repoParam ? `{repo: "${repo}"}` : ''}) if you want a graph-level scope check; git diff usually suffices.`;

    case 'cypher':
      return `\n\n---\n**Optional:** context({name: "<name>"${repoParam}}) for a result symbol, or READ gitnexus://repo/${repoPath}/schema for the schema.`;

    // Legacy tool names — still return useful hints
    case 'search':
      return `\n\n---\n**Optional:** context({name: "<symbol>"${repoParam}}) if you need callers/callees for a result.`;
    case 'explore':
      return `\n\n---\n**Optional:** impact({target: "<name>", direction: "upstream"${repoParam}}) only for multi-file risk analysis.`;
    case 'overview':
      return `\n\n---\n**Optional:** READ gitnexus://repo/${repoPath}/cluster/{name} or processes if you need to drill in.`;

    default:
      return '';
  }
}

/**
 * Create a configured MCP Server with all handlers registered.
 * Transport-agnostic — caller connects the desired transport.
 */
export function createMCPServer(backend: LocalBackend): Server {
  const require = createRequire(import.meta.url);
  const pkgVersion: string = require('../../package.json').version;
  const server = new Server(
    {
      name: 'gitnexus',
      version: pkgVersion,
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
    },
  );

  // Handle list resources request
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    const resources = getResourceDefinitions();
    return {
      resources: resources.map((r) => ({
        uri: r.uri,
        name: r.name,
        description: r.description,
        mimeType: r.mimeType,
      })),
    };
  });

  // Handle list resource templates request (for dynamic resources)
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
    const templates = getResourceTemplates();
    return {
      resourceTemplates: templates.map((t) => ({
        uriTemplate: t.uriTemplate,
        name: t.name,
        description: t.description,
        mimeType: t.mimeType,
      })),
    };
  });

  // Handle read resource request
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    try {
      const content = await readResource(uri, backend);
      return {
        contents: [
          {
            uri,
            mimeType: 'text/yaml',
            text: content,
          },
        ],
      };
    } catch (err: any) {
      return {
        contents: [
          {
            uri,
            mimeType: 'text/plain',
            text: `Error: ${err.message}`,
          },
        ],
      };
    }
  });

  // Handle list tools request
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: GITNEXUS_TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations: tool.annotations,
    })),
  }));

  // Handle tool calls — append next-step hints to guide agent workflow
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      const result = await backend.callTool(name, args);
      const resultText = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
      const hint = getNextStepHint(name, args as Record<string, any> | undefined);

      return {
        content: [
          {
            type: 'text',
            text: resultText + hint,
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${message}`,
          },
        ],
        isError: true,
      };
    }
  });

  // Handle list prompts request
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: [
      {
        name: 'detect_impact',
        description:
          'Analyze the impact of your current changes before committing. Guides through scope selection, change detection, process analysis, and risk assessment.',
        arguments: [
          {
            name: 'scope',
            description: 'What to analyze: unstaged, staged, all, or compare',
            required: false,
          },
          { name: 'base_ref', description: 'Branch/commit for compare scope', required: false },
        ],
      },
      {
        name: 'generate_map',
        description:
          'Generate architecture documentation from the knowledge graph. Creates a codebase overview with execution flows and mermaid diagrams.',
        arguments: [
          {
            name: 'repo',
            description: 'Repository name (omit if only one indexed)',
            required: false,
          },
        ],
      },
    ],
  }));

  // Handle get prompt request
  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === 'detect_impact') {
      const scope = args?.scope || 'all';
      const baseRef = args?.base_ref || '';
      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `Analyze the impact of my current code changes before committing.

Follow these steps:
1. Run \`detect_changes(${JSON.stringify({ scope, ...(baseRef ? { base_ref: baseRef } : {}) })})\` to find what changed and affected processes
2. For each changed symbol in critical processes, run \`context({name: "<symbol>"})\` to see its full reference graph
3. For any high-risk items (many callers or cross-process), run \`impact({target: "<symbol>", direction: "upstream"})\` for blast radius
4. Summarize: changes, affected processes, risk level, and recommended actions

Present the analysis as a clear risk report.`,
            },
          },
        ],
      };
    }

    if (name === 'generate_map') {
      const repo = args?.repo || '';
      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `Generate architecture documentation for this codebase using the knowledge graph.

Follow these steps:
1. READ \`gitnexus://repo/${repo || '{name}'}/context\` for codebase stats
2. READ \`gitnexus://repo/${repo || '{name}'}/clusters\` to see all functional areas
3. READ \`gitnexus://repo/${repo || '{name}'}/processes\` to see all execution flows
4. For the top 5 most important processes, READ \`gitnexus://repo/${repo || '{name}'}/process/{name}\` for step-by-step traces
5. Generate a mermaid architecture diagram showing the major areas and their connections
6. Write an ARCHITECTURE.md file with: overview, functional areas, key execution flows, and the mermaid diagram`,
            },
          },
        ],
      };
    }

    throw new Error(`Unknown prompt: ${name}`);
  });

  return server;
}

/**
 * Start the MCP server on stdio transport (for CLI use).
 */
export async function startMCPServer(backend: LocalBackend): Promise<void> {
  const server = createMCPServer(backend);

  // Idempotent global sentinel install. cli/mcp.ts calls this first thing
  // (before warnMissingOptionalGrammars / backend.init can emit to stdout);
  // calling again here is a safety net for direct callers of startMCPServer
  // (tests, future entry points). The transport's _safeStdout Proxy is a
  // second layer that guarantees transport writes reach the sentinel even
  // if anything else re-replaces process.stdout.write later. Tagged
  // transport writes (wrapped in withMcpWrite by compatible-stdio-transport.send)
  // pass through to the captured realStdoutWrite; untagged writes reaching
  // the Proxy or process.stdout get redirected to stderr with the
  // [mcp:stdout-redirect] prefix. See stdio-context.ts.
  const sentinel = installGlobalStdoutSentinel();
  const safeStdout = new Proxy(process.stdout, {
    get(target, prop, receiver) {
      if (prop === 'write') return sentinel.write;
      const val = Reflect.get(target, prop, receiver);
      return typeof val === 'function' ? val.bind(target) : val;
    },
  });
  const transport = new CompatibleStdioServerTransport(process.stdin, safeStdout);
  await server.connect(transport);

  // Surface the redirect counter on shutdown so users see the volume of
  // stray writes even when individual payloads were truncated/suppressed.
  process.on('exit', () => sentinel.flushSummary());

  // Graceful shutdown helper. Pino's default destination is `sync: false`
  // (buffered), so we must `flushLoggerSync()` before `process.exit` —
  // otherwise records emitted during disconnect/close are lost. The flush
  // is a no-op when the singleton was never used or when running under
  // vitest. See `gitnexus/src/core/logger.ts`.
  let shuttingDown = false;
  const shutdown = async (exitCode = 0) => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      await backend.disconnect();
    } catch {}
    try {
      await server.close();
    } catch {}
    const { flushLoggerSync } = await import('../core/logger.js');
    flushLoggerSync();
    process.exit(exitCode);
  };

  // Handle graceful shutdown
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Log crashes to stderr so they aren't silently lost.
  // uncaughtException is fatal — shut down.
  // unhandledRejection is logged but kept non-fatal (availability-first):
  // killing the server for one missed catch would be worse than logging it.
  process.on('uncaughtException', (err) => {
    process.stderr.write(`GitNexus MCP uncaughtException: ${err?.stack || err}\n`);
    shutdown(1);
  });
  process.on('unhandledRejection', (reason: any) => {
    process.stderr.write(`GitNexus MCP unhandledRejection: ${reason?.stack || reason}\n`);
  });

  // Handle stdio errors — stdin close means the parent process is gone
  process.stdin.on('end', shutdown);
  process.stdin.on('error', () => shutdown());
  process.stdout.on('error', () => shutdown());
}
