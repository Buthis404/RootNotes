import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import Icon from './Icon.jsx';

describe('Icon', () => {
  it('renders an svg for a known name', () => {
    const { container } = render(<Icon name="shield" />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('renders nothing inside the wrapper for an unknown name', () => {
    const { container } = render(<Icon name="does-not-exist" />);
    expect(container.querySelector('svg')).toBeNull();
    // wrapper span is still present
    expect(container.querySelector('span')).toBeInTheDocument();
  });

  it('applies the given size to the svg', () => {
    const { container } = render(<Icon name="search" size={24} />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('width', '24');
    expect(svg).toHaveAttribute('height', '24');
  });

  it('passes the colour through as the stroke', () => {
    const { container } = render(<Icon name="search" color="#ff0000" />);
    expect(container.querySelector('svg')).toHaveAttribute('stroke', '#ff0000');
  });
});
