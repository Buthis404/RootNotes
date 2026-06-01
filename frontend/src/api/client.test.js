import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { req, upload, download, BASE } from './client.ts';

function mockFetch(impl) {
  globalThis.fetch = vi.fn(impl);
}

describe('api client req()', () => {
  beforeEach(() => { vi.restoreAllMocks(); });
  afterEach(() => { vi.restoreAllMocks(); });

  it('GETs and returns parsed JSON', async () => {
    mockFetch(async () => ({ status: 200, ok: true, json: async () => ({ a: 1 }) }));
    const data = await req('GET', '/things');
    expect(data).toEqual({ a: 1 });
    expect(globalThis.fetch).toHaveBeenCalledWith(BASE + '/things', expect.objectContaining({
      method: 'GET', credentials: 'include',
    }));
  });

  it('serialises a JSON body for writes', async () => {
    mockFetch(async () => ({ status: 200, ok: true, json: async () => ({}) }));
    await req('POST', '/things', { name: 'x' });
    const opts = globalThis.fetch.mock.calls[0][1];
    expect(opts.body).toBe(JSON.stringify({ name: 'x' }));
    expect(opts.headers['Content-Type']).toBe('application/json');
  });

  it('returns null on 204 No Content', async () => {
    mockFetch(async () => ({ status: 204, ok: true }));
    expect(await req('DELETE', '/things/1')).toBeNull();
  });

  it('dispatches rt:logout and throws on 401 when auth required', async () => {
    mockFetch(async () => ({ status: 401, ok: false }));
    const onLogout = vi.fn();
    globalThis.addEventListener('rt:logout', onLogout, { once: true });
    await expect(req('GET', '/secure')).rejects.toMatchObject({ status: 401 });
    expect(onLogout).toHaveBeenCalled();
  });

  it('does not dispatch logout on 401 when auth not required', async () => {
    mockFetch(async () => ({ status: 401, ok: false, text: async () => 'nope' }));
    const onLogout = vi.fn();
    globalThis.addEventListener('rt:logout', onLogout, { once: true });
    await expect(req('GET', '/public', undefined, false)).rejects.toBeTruthy();
    expect(onLogout).not.toHaveBeenCalled();
    globalThis.removeEventListener('rt:logout', onLogout);
  });

  it('parses a 409 conflict payload into a structured error', async () => {
    mockFetch(async () => ({
      status: 409, ok: false,
      json: async () => ({ message: 'dup', code: 'duplicate', details: { field: 'name' } }),
    }));
    await expect(req('POST', '/things')).rejects.toMatchObject({
      status: 409, code: 'duplicate', message: 'dup', details: { field: 'name' },
    });
  });

  it('extracts message/code from a JSON error body on other failures', async () => {
    mockFetch(async () => ({
      status: 422, ok: false,
      text: async () => JSON.stringify({ detail: 'bad input', code: 'validation' }),
    }));
    await expect(req('POST', '/things')).rejects.toMatchObject({
      status: 422, code: 'validation', message: 'bad input',
    });
  });

  it('falls back to raw text when the error body is not JSON', async () => {
    mockFetch(async () => ({ status: 500, ok: false, text: async () => 'Server Error' }));
    await expect(req('GET', '/boom')).rejects.toMatchObject({
      status: 500, message: 'Server Error',
    });
  });
});

describe('api client upload() / download()', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it('uploads a file as multipart form data', async () => {
    mockFetch(async () => ({ ok: true, json: async () => ({ id: 'f1' }) }));
    const file = new File(['data'], 'loot.txt', { type: 'text/plain' });
    const res = await upload('/files', file);
    expect(res).toEqual({ id: 'f1' });
    const opts = globalThis.fetch.mock.calls[0][1];
    expect(opts.method).toBe('POST');
    expect(opts.body).toBeInstanceOf(FormData);
  });

  it('throws the response text when upload fails', async () => {
    mockFetch(async () => ({ ok: false, text: async () => 'too big' }));
    const file = new File(['x'], 'x.bin');
    await expect(upload('/files', file)).rejects.toThrow('too big');
  });

  it('downloads a blob', async () => {
    const blob = new Blob(['report']);
    mockFetch(async () => ({ ok: true, blob: async () => blob }));
    expect(await download('/report.pdf')).toBe(blob);
  });
});
