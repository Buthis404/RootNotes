import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import ToastContainer, { toast, toastError, toastSuccess, toastWarn } from './Toast.jsx';

describe('ToastContainer', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { act(() => { vi.runOnlyPendingTimers(); }); vi.useRealTimers(); });

  it('renders nothing when there are no toasts', () => {
    const { container } = render(<ToastContainer />);
    expect(container.firstChild).toBeNull();
  });

  it('shows a toast pushed via toast()', () => {
    render(<ToastContainer />);
    act(() => { toast('hello world'); });
    expect(screen.getByText('hello world')).toBeInTheDocument();
  });

  it('auto-removes a toast after 4s', () => {
    render(<ToastContainer />);
    act(() => { toastSuccess('done'); });
    expect(screen.getByText('done')).toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(4000); });
    expect(screen.queryByText('done')).toBeNull();
  });

  it('supports multiple severities concurrently', () => {
    render(<ToastContainer />);
    act(() => { toastError('err'); toastWarn('warn'); });
    expect(screen.getByText('err')).toBeInTheDocument();
    expect(screen.getByText('warn')).toBeInTheDocument();
  });

  it('toast() is a no-op when no container is mounted', () => {
    expect(() => toast('orphan')).not.toThrow();
  });
});
