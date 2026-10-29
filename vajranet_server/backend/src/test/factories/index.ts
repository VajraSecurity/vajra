import { VajraUser, UserRole } from '../../orm/entities/users/Users';
import { JwtPayload } from '../../types/JwtPayload';

let nextId = 1;

export function makeUser(overrides: Partial<VajraUser> = {}): VajraUser {
  const user = new VajraUser();
  user.id = overrides.id ?? nextId++;
  user.name = overrides.name ?? 'Test User';
  user.email = overrides.email ?? `user${user.id}@example.com`;
  user.mobile = overrides.mobile ?? '9999999999';
  user.company = overrides.company ?? 'Acme Inc';
  user.address = overrides.address ?? '123 Main St';
  user.role = overrides.role ?? ('Viewer' as UserRole);
  user.password_hash = overrides.password_hash ?? null;
  user.created_at = overrides.created_at ?? new Date();
  user.updated_at = overrides.updated_at ?? new Date();
  user.forcePasswordChange = overrides.forcePasswordChange ?? false;
  user.session_version = overrides.session_version ?? 0;
  user.suspended = overrides.suspended ?? false;
  user.mfa_secret = overrides.mfa_secret ?? null;
  user.mfa_enabled = overrides.mfa_enabled ?? false;
  user.recovery_codes = overrides.recovery_codes ?? [];
  user.security_question_1 = overrides.security_question_1 ?? null;
  user.security_answer_1_hash = overrides.security_answer_1_hash ?? null;
  user.security_question_2 = overrides.security_question_2 ?? null;
  user.security_answer_2_hash = overrides.security_answer_2_hash ?? null;
  return user;
}

export function makeSuperAdmin(overrides: Partial<VajraUser> = {}): VajraUser {
  return makeUser({ role: 'Super Administrator' as UserRole, ...overrides });
}

export function makeJwtPayload(overrides: Partial<JwtPayload> = {}): JwtPayload {
  return {
    id: overrides.id ?? 1,
    name: overrides.name ?? 'Test User',
    email: overrides.email ?? 'user1@example.com',
    role: overrides.role ?? 'Viewer',
    created_at: overrides.created_at ?? new Date(),
    session_version: overrides.session_version ?? 0,
    // Explicit `sessionId: undefined` must stay undefined (tests use it to skip the
    // session-repo lookup branch in validateSessionVersion) — only default when the
    // key is absent entirely. `overrides.sessionId ?? 1` would collapse both cases.
    sessionId: 'sessionId' in overrides ? overrides.sessionId : 1,
    force_password_change: overrides.force_password_change ?? false,
  };
}
