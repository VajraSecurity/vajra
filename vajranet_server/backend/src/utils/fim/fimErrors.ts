/** Thrown on invalid FIM input (maps to HTTP 422). Lives here so leaf modules can share it without import cycles. */
export class FimValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FimValidationError';
  }
}
