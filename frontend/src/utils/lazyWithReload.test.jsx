import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Suspense, Component, createElement } from 'react';
import lazyWithReload from './lazyWithReload.js';

const RELOAD_FLAG = 'rt_chunk_reload_attempted';

// Catch the re-thrown ChunkLoadError so it never escapes as an unhandled
// rejection that would pollute other test files in a parallel run.
class Boundary extends Component {
  constructor(props) { super(props); this.state = { failed: false }; }
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed
      ? createElement('div', null, 'errored')
      : this.props.children;
  }
}

function renderLazy(Comp) {
  return render(
    createElement(Boundary, null,
      createElement(Suspense, { fallback: createElement('div', null, 'loading') },
        createElement(Comp))),
  );
}

describe('lazyWithReload', () => {
  let reloadSpy;

  beforeEach(() => {
    sessionStorage.clear();
    reloadSpy = vi.fn();
    // jsdom location.reload is not implemented — replace it.
    Object.defineProperty(globalThis, 'location', {
      value: { ...globalThis.location, reload: reloadSpy },
      writable: true,
      configurable: true,
    });
    // React logs caught errors via console.error — keep test output clean.
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => { vi.restoreAllMocks(); });

  it('renders the component when the loader succeeds', async () => {
    const Ok = lazyWithReload(async () => ({
      default: () => createElement('div', null, 'loaded-ok'),
    }));
    renderLazy(Ok);
    expect(await screen.findByText('loaded-ok')).toBeInTheDocument();
    expect(reloadSpy).not.toHaveBeenCalled();
  });

  it('reloads once and sets a flag on a chunk-load error', async () => {
    const err = new Error('error loading dynamically imported module: x.js');
    const Broken = lazyWithReload(() => Promise.reject(err));
    renderLazy(Broken);
    await waitFor(() => expect(reloadSpy).toHaveBeenCalledTimes(1));
    expect(sessionStorage.getItem(RELOAD_FLAG)).toBe('1');
    // never-resolving promise keeps Suspense in the loading state
    expect(screen.getByText('loading')).toBeInTheDocument();
  });

  it('gives up (clears flag, surfaces error) when reload was already attempted', async () => {
    sessionStorage.setItem(RELOAD_FLAG, '1');
    const err = Object.assign(new Error('boom'), { name: 'ChunkLoadError' });
    const Broken = lazyWithReload(() => Promise.reject(err));
    renderLazy(Broken);
    expect(await screen.findByText('errored')).toBeInTheDocument();
    expect(sessionStorage.getItem(RELOAD_FLAG)).toBeNull();
    expect(reloadSpy).not.toHaveBeenCalled();
  });

  it('re-throws a non-chunk error without reloading', async () => {
    const Broken = lazyWithReload(() => Promise.reject(new Error('logic bug')));
    renderLazy(Broken);
    expect(await screen.findByText('errored')).toBeInTheDocument();
    expect(reloadSpy).not.toHaveBeenCalled();
  });
});
