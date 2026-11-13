import { createHmac } from 'node:crypto'

// Visa sandbox client using X-Pay Token. X-Pay Token signs "<timestamp><resource path><query string><body>".
// For these APIs the resource path is the request path with the leading "/" and the first segment
// (the context path, e.g. "v1" or "vmrs") removed.

export const resourcePathOf = (path) => path.replace(/^\//, '').split('/').slice(1).join('/')

export function createVisaClient({ apiKey, sharedSecret, base = 'https://sandbox.api.visa.com', now = () => Date.now() }) {
  return async function visa(method, path, body) {
    const query = `apikey=${apiKey}`
    const raw = body === undefined ? '' : JSON.stringify(body)
    const ts = String(Math.floor(now() / 1000))
    const token = `xv2:${ts}:${createHmac('sha256', sharedSecret).update(ts + resourcePathOf(path) + query + raw).digest('hex')}`
    const res = await fetch(`${base}${path}?${query}`, {
      method,
      headers: { 'X-PAY-TOKEN': token, Accept: 'application/json', ...(raw ? { 'Content-Type': 'application/json' } : {}) },
      body: raw || undefined,
    })
    const text = await res.text()
    let json = null
    try { json = JSON.parse(text) } catch {}
    return { status: res.status, json, text, correlation: res.headers.get('x-correlation-id') }
  }
}
