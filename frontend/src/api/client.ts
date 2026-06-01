export const BASE = '/api';

export interface ApiError extends Error {
  status: number;
  code?: string;
  details?: unknown;
  serverNote?: string;
}

function makeApiError(msg: string, status: number, code?: string, details?: unknown, serverNote?: string): ApiError {
  const err = new Error(msg) as ApiError;
  err.status = status;
  if (code !== undefined) err.code = code;
  if (details !== undefined) err.details = details;
  if (serverNote !== undefined) err.serverNote = serverNote;
  return err;
}

export async function req(
  method: string,
  path: string,
  body?: unknown,
  authRequired = true,
): Promise<unknown> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const opts: RequestInit = { method, headers, credentials: 'include' };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  if (res.status === 204) return null;
  if (res.status === 401 && authRequired) {
    globalThis.dispatchEvent(new Event('rt:logout'));
    throw makeApiError('Unauthorized', 401);
  }
  if (res.status === 409) {
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    const msg = (data.message as string) || (data.detail as string) || 'conflict';
    throw makeApiError(msg, 409, (data.code as string) || 'conflict', data.details, msg);
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    let code: string | undefined;
    let details: unknown;
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      msg = (parsed.message as string) || (parsed.detail as string) || text;
      code = parsed.code as string | undefined;
      details = parsed.details;
    } catch {}
    throw makeApiError(msg, res.status, code, details);
  }
  return res.json();
}

export async function upload(path: string, file: File, fieldName = 'file'): Promise<unknown> {
  const form = new FormData();
  form.append(fieldName, file);
  const res = await fetch(BASE + path, {
    method: 'POST',
    body: form,
    credentials: 'include',
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function download(path: string): Promise<Blob> {
  const res = await fetch(BASE + path, { credentials: 'include' });
  if (!res.ok) throw new Error(await res.text());
  return res.blob();
}
