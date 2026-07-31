import { describe, expect, it } from 'vitest';
import { preprocessSwiftConditionalDirectives } from '../../src/core/ingestion/languages/swift/conditional-directive-preprocess.js';

describe('Swift conditional-directive preprocessing', () => {
  it('blanks only indented conditional directives, including conditions and comments', () => {
    const source = [
      '#if os(macOS)',
      'class TopLevel {}',
      '#endif',
      'class Outer {',
      '  #if os(iOS) // platform branch',
      '  enum A { case x }',
      '\t#elseif DEBUG && canImport(UIKit) // fallback',
      '  enum B { case y }',
      '  #else',
      '  enum C { case z }',
      '  #endif // end branch',
      '}',
    ].join('\n');

    const rewritten = preprocessSwiftConditionalDirectives(source);
    const lines = rewritten.split('\n');

    expect(lines[0]).toBe('#if os(macOS)');
    expect(lines[2]).toBe('#endif');
    expect(lines[4]).toBe(''.padEnd(lines[4]!.length, ' '));
    expect(lines[6]).toBe(''.padEnd(lines[6]!.length, ' '));
    expect(lines[8]).toBe(''.padEnd(lines[8]!.length, ' '));
    expect(lines[10]).toBe(''.padEnd(lines[10]!.length, ' '));
    expect(lines[5]).toBe('  enum A { case x }');
    expect(lines[11]).toBe('}');
  });

  it('preserves JavaScript string length and newline count', () => {
    const source = '#if DEBUG\nclass Outer {\n  #else\n}\n#endif\n';
    const rewritten = preprocessSwiftConditionalDirectives(source);

    expect(rewritten).toHaveLength(source.length);
    expect(rewritten.match(/\n/g)?.length ?? 0).toBe(source.match(/\n/g)?.length ?? 0);
    expect(rewritten.slice(0, '#if DEBUG'.length)).toBe('#if DEBUG');
  });

  it('returns directive-free Swift source unchanged', () => {
    const source = 'class Plain {\n  var value: Int = 0\n  func read() -> Int { value }\n}\n';

    expect(preprocessSwiftConditionalDirectives(source)).toBe(source);
  });

  it('preserves CRLF line endings and offsets', () => {
    const source = 'class Outer {\r\n\t#if os(iOS)\r\n\tenum A { case x }\r\n\t#endif\r\n}\r\n';
    const rewritten = preprocessSwiftConditionalDirectives(source);

    expect(rewritten).toHaveLength(source.length);
    expect(rewritten.match(/\r\n/g)?.length ?? 0).toBe(source.match(/\r\n/g)?.length ?? 0);
    expect(rewritten.indexOf('enum A')).toBe(source.indexOf('enum A'));
    expect(rewritten).toContain('          \r\n');
    expect(rewritten).toContain('      \r\n');
    expect(rewritten).toContain('\tenum A { case x }\r\n');
  });
});
