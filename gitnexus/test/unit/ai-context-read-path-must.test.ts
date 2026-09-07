import { describe, it, expect } from 'vitest';
import { generateGitNexusContent } from '../../src/cli/ai-context.js';

// The fork deliberately reverses #3076's mandatory read-path policy: graph
// tools are optional even in read-only sessions, and local work can use grep.
describe('generateGitNexusContent keeps graph exploration optional', () => {
  const stats = { nodes: 50, edges: 100, processes: 5 };

  it.each([true, false])('permits local tools when hasPdg=%s', (hasPdg) => {
    const content = generateGitNexusContent('ReadPathProject', stats, { hasPdg });
    expect(content).toContain('not a default step for every edit');
    expect(content).toContain('HTML/CSS/markup');
    expect(content).toContain('Prefer normal editor tools');
    expect(content).not.toMatch(/\b(?:MUST|NEVER|ALWAYS)\b/);
    expect(content).not.toContain('Graph first');
    if (hasPdg) expect(content).toContain('pdg_query');
  });

  it('keeps Spring evidence guidance without adding a graph gate', () => {
    const content = generateGitNexusContent('SpringProject', stats, { hasSpringActuator: true });
    expect(content).toContain('Spring Actuator runtime evidence is enabled');
    expect(content).toContain('runtimeConfirmed === true');
    expect(content).not.toMatch(/\b(?:MUST|NEVER|ALWAYS)\b/);
  });

  it('omits PDG tool suggestions when that layer is absent', () => {
    const withoutPdg = generateGitNexusContent('PlainProject', stats);
    expect(withoutPdg).toContain('Prefer normal editor tools');
    expect(withoutPdg).not.toContain('pdg_query');
  });
});
