export const BASE = '/api';

export async function req(method, path, body, authRequired = true) {
  const headers = { 'Content-Type': 'application/json' };
  const opts = { method, headers, credentials: 'include' };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  if (res.status === 204) return null;
  if (res.status === 401 && authRequired) {
    window.dispatchEvent(new Event('rt:logout'));
    throw new Error('Unauthorized');
  }
  if (res.status === 409) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data.message || data.detail || 'conflict');
    err.status = 409;
    err.code = data.code || 'conflict';
    err.details = data.details;
    err.serverNote = data.message || data.detail;
    throw err;
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    let code, details;
    try {
      const parsed = JSON.parse(text);
      // Unified error contract (v0.3.2+): {code, message, details?, detail}.
      // Older endpoints / unhandled exceptions may still emit bare {detail}.
      msg = parsed.message || parsed.detail || text;
      code = parsed.code;
      details = parsed.details;
    } catch {}
    const err = new Error(msg);
    err.status = res.status;
    if (code) err.code = code;
    if (details !== undefined) err.details = details;
    throw err;
  }
  return res.json();
}

export async function upload(path, file, fieldName = 'file') {
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

export async function download(path) {
  const res = await fetch(BASE + path, { credentials: 'include' });
  if (!res.ok) throw new Error(await res.text());
  return res.blob();
}
