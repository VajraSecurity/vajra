import { createContext, useContext } from 'react';

export type AuthStatusState = {
  isValid: boolean;
  forcePasswordChange: boolean;
  loading: boolean;
  error: string | null;
};

export type AuthStatusContextType = AuthStatusState & {
  refetch: (opts?: { silent?: boolean }) => Promise<void>;
};

export const AuthStatusContext = createContext<AuthStatusContextType | undefined>(undefined);

export const useAuthStatus = (): AuthStatusContextType => {
  const ctx = useContext(AuthStatusContext);
  if (!ctx) throw new Error('useAuthStatus must be used within <AuthStatusProvider>');
  return ctx;
};
