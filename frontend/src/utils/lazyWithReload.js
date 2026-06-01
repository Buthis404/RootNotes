import { lazy } from 'react';

/**
 * React.lazy wrapper that survives Vite chunk-hash rotation on rebuild.
 *
 * When the backend rebuilds the frontend bundle, Vite emits new
 * content-hashed chunk filenames (`AttackGraphView-Ctw9LJ6W.js` →
 * `AttackGraphView-XYZ.js`). Any tab that was already loaded still
 * holds references to the OLD chunk URLs in its in-memory module
 * graph. When the user clicks a tab that needs that chunk, the
 * dynamic `import()` 404s and React throws:
 *
 *   "TypeError: error loading dynamically imported module: …"
 *
 * Strategy:
 *  1. First attempt — call the loader.
 *  2. On `ChunkLoadError`/`error loading dynamically imported module`,
 *     set a sessionStorage flag and force a single page reload.
 *     The reload pulls a fresh `index.html` which references the
 *     current chunk hashes, so the next attempt succeeds.
 *  3. If the flag is already set (we've reloaded once and still see
 *     the error), give up and re-throw so the user sees a real error
 *     instead of an infinite reload loop.
 */
const RELOAD_FLAG = 'rt_chunk_reload_attempted';

export default function lazyWithReload(loader) {
  return lazy(() =>
    loader().catch((err) => {
      const msg = String(err && (err.message || err));
      const isChunkError =
        err?.name === 'ChunkLoadError' ||
        /error loading dynamically imported module/i.test(msg) ||
        /Failed to fetch dynamically imported module/i.test(msg) ||
        /Loading chunk \d+ failed/i.test(msg);

      if (isChunkError && typeof globalThis !== 'undefined') {
        try {
          if (!sessionStorage.getItem(RELOAD_FLAG)) {
            sessionStorage.setItem(RELOAD_FLAG, '1');
            globalThis.location.reload();
            // Return a never-resolving promise so React doesn't render
            // an error boundary while the reload is in flight.
            return new Promise(() => {});
          }
          // Reload already attempted — clear the flag and bubble up
          sessionStorage.removeItem(RELOAD_FLAG);
        } catch {
          // sessionStorage unavailable (private mode, etc.) — just reload
          globalThis.location.reload();
          return new Promise(() => {});
        }
      }
      throw err;
    }),
  );
}
