import { createContext, useContext } from 'react';

export interface ForcePasswordChangeContextType {
  forcePasswordChange: boolean;
  setForcePasswordChange: (value: boolean) => void;
}

export const ForcePasswordChangeContext = createContext<ForcePasswordChangeContextType | undefined>(undefined);

export const useForcePasswordChange = () => {
  const context = useContext(ForcePasswordChangeContext);
  if (!context) {
    throw new Error(
      'useForcePasswordChange must be used within ForcePasswordChangeProvider'
    );
  }
  return context;
};
