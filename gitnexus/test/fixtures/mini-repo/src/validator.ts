export interface ValidationResult {
  valid: boolean;
  value: string;
}

export function validateInput(input: string): ValidationResult {
  const cleaned = sanitize(input);
  if (!cleaned || cleaned.trim().length === 0) {
    return { valid: false, value: '' };
  }
  return { valid: true, value: cleaned.trim() };
}

export function sanitize(input: string): string {
  return input.replace(/[<>]/g, '');
}
