import React, { useState } from 'react';
import type { ReactNode } from 'react';
import { ForcePasswordChangeContext } from './useForcePasswordChange';

export const ForcePasswordChangeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [forcePasswordChange, setForcePasswordChange] = useState(false);

  const handleSetForcePasswordChange = (value: boolean) => {
    setForcePasswordChange(value);
  };

  return (
    <ForcePasswordChangeContext.Provider
      value={{
        forcePasswordChange,
        setForcePasswordChange: handleSetForcePasswordChange,
      }}
    >
      {children}
    </ForcePasswordChangeContext.Provider>
  );
};
