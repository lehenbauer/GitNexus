import { describe, it, expect } from 'vitest';
import { generateGitNexusContent } from '../../src/cli/ai-context.js';

// Preserve the meaning of incomplete graph results without turning an optional
// tool into a compulsory pre-edit workflow. This applies with or without PDG.
describe('generateGitNexusContent explains incomplete graph evidence', () => {
  const stats = { nodes: 50, edges: 100, processes: 5 };

  it.each([true, false])('keeps the caveat optional when hasPdg=%s', (hasPdg) => {
    const content = generateGitNexusContent('UnknownRiskProject', stats, { hasPdg });
    for (const fragment of [
      'risk: UNKNOWN',
      'partial: true',
      'truncated: true',
      'incomplete evidence',
    ]) {
      expect(content).toContain(fragment);
    }
    expect(content).toContain('confirm relevant details in source');
    expect(content).toContain('**Optional regression review:**');
    expect(content).not.toMatch(/\b(?:MUST|NEVER|ALWAYS)\b/);
  });

  it('keeps PDG tools gated while explaining UNKNOWN on a plain index', () => {
    const withoutPdg = generateGitNexusContent('PlainProject', stats);
    expect(withoutPdg).toContain('risk: UNKNOWN');
    expect(withoutPdg).not.toContain('pdg_query');
  });
});
