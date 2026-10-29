import React from 'react';
import { Checkbox as MuiCheckbox } from '@mui/material';
import type { CheckboxProps as MuiCheckboxProps } from '@mui/material';

export type CheckboxProps = MuiCheckboxProps;

export const Checkbox = React.forwardRef<HTMLButtonElement, CheckboxProps>(
  ({ sx, ...props }, ref) => {
    return (
      <MuiCheckbox
        ref={ref}
        sx={{
          padding: '0px',
          color: '#D1D5DB',
          '&.Mui-checked': { color: '#010101' },
          '&.MuiCheckbox-indeterminate': { color: '#010101' },
          ...sx,
        }}
        {...props}
      />
    );
  }
);

Checkbox.displayName = 'Checkbox';
