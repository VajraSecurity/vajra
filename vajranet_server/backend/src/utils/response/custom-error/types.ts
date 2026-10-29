export type ErrorResponse = {
  status: 'Error';
  message: string;
  errorType: ErrorType;
  errors: string[] | null;
  errorRaw: any;
  errorsValidation: ErrorValidation[] | null;
  stack?: string;
};

export type ErrorType = 'General' | 'Raw' | 'Validation' | 'Unauthorized' | 'Database' | 'Conflict';

export type ErrorValidation = { [key: string]: string };
