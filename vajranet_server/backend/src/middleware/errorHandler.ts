import { Request, Response, NextFunction } from 'express';
import { getLogger } from '../utils/logger';
import {
  STATUS_BAD_REQUEST,
  STATUS_UNAUTHORIZED,
  STATUS_FORBIDDEN,
  STATUS_NOT_FOUND,
  STATUS_CONFLICT,
  STATUS_UNPROCESSABLE_ENTITY,
  STATUS_TOO_MANY_REQUESTS,
  STATUS_FAILED_DEPENDENCY,
  STATUS_INTERNAL_SERVER_ERROR,
  STATUS_SERVICE_UNAVAILABLE,
  STATUS_GATEWAY_TIMEOUT,
} from '../consts';

const log = getLogger('errorHandler');

interface CustomErrorResponse {
  status: string;
  message: string;
  statusCode?: number;
  stack?: string;
  errorType?: string;
  errors?: any;
}

export const errorHandler = (err: any, req: Request, res: Response, _next: NextFunction) => {
  // Handle JSON parsing errors
  if ('type' in err && err['type'] === 'entity.parse.failed') {
    log.warn({ method: req.method, url: req.originalUrl }, 'Malformed request body: JSON parse failed');
    return res.status(STATUS_BAD_REQUEST).json({
      status: 'Error',
      message: 'Invalid content type. Only JSON is supported.',
      statusCode: STATUS_BAD_REQUEST,
    });
  }

  // Handle custom error objects (CustomError class)
  //
  // `JSON` on CustomError is a getter that allocates a fresh response object on
  // every read, including two process.env lookups (see
  // utils/response/custom-error/CustomError.ts), so read it once. Every
  // 401/403/422/429 in the middleware layer funnels through here, which is
  // exactly the path that gets hot under a credential-stuffing flood.
  //
  // A ternary rather than hoisting `const errJson = err.JSON`: `err` is
  // duck-typed, not necessarily a CustomError, and the short-circuit on
  // HttpStatusCode is what keeps `.JSON` from being read on error objects that
  // have no such property.
  const errJson = err.HttpStatusCode ? err.JSON : undefined;
  if (errJson) {
    // Same 4xx/5xx split as the generic path below. This branch returns before
    // reaching it, so without logging here a CustomError — most auth, CSRF and
    // validation failures — would leave no trace. CustomError carries no request
    // context and no request id is threaded through the child loggers, so
    // method and url are attached explicitly.
    const customStatusCode = err.HttpStatusCode;
    const customErrorType = errJson.errorType;
    if (customStatusCode >= 500) {
      log.error({ err, statusCode: customStatusCode, errorType: customErrorType, method: req.method, url: req.originalUrl }, err.message || 'Internal Server Error');
    } else if (customStatusCode >= 400) {
      log.warn({ statusCode: customStatusCode, errorType: customErrorType, method: req.method, url: req.originalUrl }, err.message || 'Request failed');
    }
    return res.status(err.HttpStatusCode).json(errJson);
  }

  // Extract status code with fallback
  let statusCode = err.statusCode || err.status || STATUS_INTERNAL_SERVER_ERROR;
  const message = err.message || 'Internal Server Error';

  // Map error types to appropriate HTTP status codes
  if (err.errorType) {
    switch (err.errorType.toLowerCase()) {
      case 'validation':
        statusCode = STATUS_UNPROCESSABLE_ENTITY;
        break;
      case 'notfound':
        statusCode = STATUS_NOT_FOUND;
        break;
      case 'conflict':
      case 'duplicate':
        statusCode = STATUS_CONFLICT;
        break;
      case 'ratelimit':
      case 'toomanyrequests':
        statusCode = STATUS_TOO_MANY_REQUESTS;
        break;
      case 'unauthorized':
        statusCode = STATUS_UNAUTHORIZED;
        break;
      case 'forbidden':
        statusCode = STATUS_FORBIDDEN;
        break;
      case 'database':
        statusCode = statusCode === STATUS_INTERNAL_SERVER_ERROR ? STATUS_SERVICE_UNAVAILABLE : statusCode;
        break;
      case 'timeout':
        statusCode = STATUS_GATEWAY_TIMEOUT;
        break;
      case 'upstream':
      case 'external':
        statusCode = STATUS_FAILED_DEPENDENCY;
        break;
    }
  }

  // Log errors: server-side failures (5xx) get the full error with stack;
  // client errors (4xx) get a lighter warn since they're expected traffic,
  // not application faults.
  if (statusCode >= 500) {
    log.error({ err, statusCode, errorType: err.errorType, method: req.method, url: req.originalUrl }, message);
  } else if (statusCode >= 400) {
    log.warn({ statusCode, errorType: err.errorType, method: req.method, url: req.originalUrl }, message);
  }

  // Build response
  const responseBody: CustomErrorResponse = {
    status: 'Error',
    message,
    statusCode,
  };

  // Include stack trace only in development
  if (process.env.NODE_ENV === 'development' && err.stack) {
    responseBody.stack = err.stack;
  }

  // Include additional error details if available
  if (err.errorType) {
    responseBody.errorType = err.errorType;
  }

  if (err.errors || err.errorsValidation) {
    responseBody.errors = err.errors || err.errorsValidation;
  }

  return res.status(statusCode).json(responseBody);
};
