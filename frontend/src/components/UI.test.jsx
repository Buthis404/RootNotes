import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  StatusDot, PhaseTag, Badge, HostStatusBadge, CredTypeBadge,
  Btn, SearchBar, FieldInput, TagEditor,
} from './UI.jsx';

describe('presentational badges', () => {
  it('StatusDot renders a coloured dot', () => {
    const { container } = render(<StatusDot status="active" />);
    expect(container.querySelector('span')).toBeInTheDocument();
  });

  it('PhaseTag shows the phase label', () => {
    render(<PhaseTag phase="recon" />);
    expect(screen.getByText('recon')).toBeInTheDocument();
  });

  it('Badge shows its label', () => {
    render(<Badge label="HIGH" color="#fff" />);
    expect(screen.getByText('HIGH')).toBeInTheDocument();
  });

  it('HostStatusBadge falls back to ? for unknown status', () => {
    render(<HostStatusBadge status="bogus" />);
    expect(screen.getByText('?')).toBeInTheDocument();
  });

  it('CredTypeBadge falls back to the raw type label', () => {
    render(<CredTypeBadge type="weirdtype" />);
    expect(screen.getByText('weirdtype')).toBeInTheDocument();
  });
});

describe('Btn', () => {
  it('fires onClick', async () => {
    const onClick = vi.fn();
    render(<Btn onClick={onClick}>Go</Btn>);
    await userEvent.click(screen.getByRole('button', { name: 'Go' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('renders an icon when icon prop is given', () => {
    const { container } = render(<Btn icon="plus">Add</Btn>);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });
});

describe('SearchBar', () => {
  it('calls onChange with the typed value', async () => {
    const onChange = vi.fn();
    render(<SearchBar value="" onChange={onChange} />);
    await userEvent.type(screen.getByPlaceholderText('Search...'), 'a');
    expect(onChange).toHaveBeenCalledWith('a');
  });
});

describe('FieldInput', () => {
  it('renders a textarea when textarea=true', () => {
    const { container } = render(
      <FieldInput label="Body" value="" onChange={() => {}} textarea />);
    expect(container.querySelector('textarea')).toBeInTheDocument();
  });

  it('renders an input otherwise and reports changes', async () => {
    const onChange = vi.fn();
    render(<FieldInput label="Name" value="" onChange={onChange} placeholder="n" />);
    await userEvent.type(screen.getByPlaceholderText('n'), 'x');
    expect(onChange).toHaveBeenCalledWith('x');
  });
});

describe('TagEditor', () => {
  it('shows "No tags" when empty and lists existing tags', () => {
    render(<TagEditor label="Tags" tags={['alpha']} onChange={() => {}} />);
    expect(screen.getByText('alpha')).toBeInTheDocument();
    render(<TagEditor label="Tags" tags={[]} onChange={() => {}} />);
    expect(screen.getByText('No tags')).toBeInTheDocument();
  });

  it('adds a deduplicated tag via the Add button', async () => {
    const onChange = vi.fn();
    render(<TagEditor label="Tags" tags={['a']} onChange={onChange} placeholder="add tag" />);
    await userEvent.type(screen.getByPlaceholderText('add tag'), 'b');
    await userEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(onChange).toHaveBeenCalledWith(['a', 'b']);
  });

  it('ignores blank input', async () => {
    const onChange = vi.fn();
    render(<TagEditor label="Tags" tags={[]} onChange={onChange} />);
    await userEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('removes a tag', async () => {
    const onChange = vi.fn();
    const { container } = render(
      <TagEditor label="Tags" tags={['x', 'y']} onChange={onChange} />);
    // each tag has a delete button (svg close icon)
    const delButtons = container.querySelectorAll('span button');
    await userEvent.click(delButtons[0]);
    expect(onChange).toHaveBeenCalledWith(['y']);
  });
});
