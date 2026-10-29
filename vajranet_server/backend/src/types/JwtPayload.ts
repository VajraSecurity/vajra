export type JwtPayload = {
  id: number;
  name: string;
  email: string;
  role?: 'Super Administrator' | 'Group Admin' | 'Viewer';
  created_at: Date;
  session_version?: number;
  sessionId?: number;
  force_password_change?: boolean;
  // Present only on the interim MFA-challenge token (createMfaToken), which is
  // signed with the same ACCESS_JWT_SECRET as a real access token but
  // represents a session that has only completed the first (password) factor.
  // Every verifier of an ACCESS_JWT_SECRET-signed token must reject a payload
  // carrying this — see isMfaChallengeToken in middleware/checkJwt.ts.
  mfaToken?: boolean;
};
