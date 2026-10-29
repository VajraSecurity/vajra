/**
 * Small per-request accessor helpers shared by controllers that log an audit
 * trail entry (client IP) or need the authenticated caller's JWT payload.
 */

import { Request } from 'express';
import { JwtPayload } from '../types/JwtPayload';

/** The authenticated caller's JWT payload, as attached by the auth middleware. */
export function jwtFrom(req: Request): JwtPayload | undefined {
  return (req as any).jwtPayload as JwtPayload | undefined;
}

/** Best-effort client IP for audit-trail logging, falling back to 'unknown' when neither is available. */
export function clientIpFrom(req: Request): string {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}
