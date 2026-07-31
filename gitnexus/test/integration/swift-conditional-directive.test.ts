import { afterAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runPipelineFromRepo } from '../../src/core/ingestion/pipeline.js';
import { isLanguageAvailable } from '../../src/core/tree-sitter/parser-loader.js';
import { SupportedLanguages } from '../../src/config/supported-languages.js';

const swiftFixture = `class Outer {
  enum A { case x }
  #if os(iOS)
  enum B { case y }
  #endif
}
`;

const swiftAvailable = isLanguageAvailable(SupportedLanguages.Swift);
const scratchDirs: string[] = [];

describe.skipIf(!swiftAvailable)('Swift conditional-directive pipeline regression', () => {
  afterAll(() => {
    for (const scratchDir of scratchDirs) fs.rmSync(scratchDir, { recursive: true, force: true });
  });

  it('keeps Outer and both nested declarations in the real worker pipeline', async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'gitnexus-swift-directive-'));
    scratchDirs.push(repo);
    fs.writeFileSync(path.join(repo, 'Fixture.swift'), swiftFixture, 'utf8');

    const result = await runPipelineFromRepo(repo, () => {}, {
      workerPoolSize: 1,
      workerThresholdsForTest: { minFiles: 1, minBytes: 1 },
    });
    const names = new Set<string>();
    result.graph.forEachNode((node) => {
      if (node.properties.filePath?.endsWith('Fixture.swift')) names.add(node.properties.name);
    });

    for (const name of ['Outer', 'A', 'B']) expect(names.has(name)).toBe(true);
  }, 60000);
});
