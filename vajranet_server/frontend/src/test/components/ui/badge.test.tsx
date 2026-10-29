import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Badge } from '@/components/ui/badge';

describe('Badge', () => {
  it('renders its children', () => {
    render(<Badge>Active</Badge>);
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('defaults to the neutral variant', () => {
    render(<Badge>Default</Badge>);
    expect(screen.getByText('Default')).toHaveClass('bg-slate-100');
  });

  it('applies the requested variant', () => {
    render(<Badge variant="destructive">Failed</Badge>);
    expect(screen.getByText('Failed')).toHaveClass('bg-red-50');
  });

  it('renders a status dot only when dot is set, colored by variant', () => {
    const { container, rerender } = render(<Badge variant="success">OK</Badge>);
    expect(container.querySelector('span > span')).not.toBeInTheDocument();

    rerender(
      <Badge variant="success" dot>
        OK
      </Badge>,
    );
    const dot = container.querySelector('span > span');
    expect(dot).toBeInTheDocument();
    expect(dot).toHaveClass('bg-emerald-500');
  });
});
