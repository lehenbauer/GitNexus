const SWIFT_INDENTED_CONDITIONAL_DIRECTIVE_RE =
  /(^[ \t]+#(?:if|elseif|else|endif)\b[^\r\n]*)(?=\r?$)/gm;

/**
 * Blank indented Swift conditional-compilation directives before parsing.
 *
 * tree-sitter-swift 0.7.1 does not admit these directives inside a class body,
 * so error recovery can discard the enclosing declaration. Replacing only the
 * directive text with spaces preserves source length, line endings, and all
 * declaration offsets. Top-level directives are left intact because they are
 * valid source-file members in the grammar.
 */
export function preprocessSwiftConditionalDirectives(sourceText: string): string {
  return sourceText.replace(SWIFT_INDENTED_CONDITIONAL_DIRECTIVE_RE, (line) =>
    line.replace(/[^\r\n]/g, ' '),
  );
}
