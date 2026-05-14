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
    const data = await res.json();
    const err = new Error('conflict');
    err.status = 409;
    err.serverNote = data.detail;
    throw err;
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try { msg = JSON.parse(text).detail || text; } catch {}
    throw new Error(msg);
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
