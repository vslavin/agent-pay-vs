import { createPublicKey, verify } from 'node:crypto'

// Verifies an OpenID Connect ID token (RS256) against a JSON Web Key Set. Pure: the caller supplies the keys and the
// clock. This is how the wallet service checks that a user really signed in again: the proof is Keycloak's own
// signature, not the app's word. Only RS256 is accepted (Keycloak's default); "none" and HMAC tokens are refused.

const b64uJson = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'))

export function decodeIdToken(token) {
  if (typeof token !== 'string' || token.length > 20_000) return null
  const parts = token.split('.')
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return null
  try { return { header: b64uJson(parts[0]), claims: b64uJson(parts[1]), signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') } } catch { return null }
}

// jwks: { keys: [...] }. Returns { ok: true, header, claims } or { ok: false, reason }.
export function verifyIdToken(token, { jwks, issuer, audience, now = Date.now() }) {
  const t = decodeIdToken(token)
  if (!t) return { ok: false, reason: 'malformed token' }
  if (t.header.alg !== 'RS256') return { ok: false, reason: `unsupported algorithm ${String(t.header.alg).slice(0, 12)}` }
  const jwk = (jwks?.keys ?? []).find((k) => k.kid === t.header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig'))
  if (!jwk) return { ok: false, reason: 'unknown signing key' }
  let good = false
  try { good = verify('RSA-SHA256', Buffer.from(t.signingInput), createPublicKey({ key: jwk, format: 'jwk' }), t.signature) } catch { good = false }
  if (!good) return { ok: false, reason: 'bad signature' }
  const c = t.claims
  const nowSec = Math.floor(now / 1000)
  if (c.iss !== issuer) return { ok: false, reason: 'wrong issuer' }
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud]
  if (!aud.includes(audience)) return { ok: false, reason: 'wrong audience' }
  if (!Number.isInteger(c.exp) || nowSec >= c.exp) return { ok: false, reason: 'token expired' }
  if (!Number.isInteger(c.iat) || c.iat > nowSec + 60) return { ok: false, reason: 'token issued in the future' }
  return { ok: true, header: t.header, claims: c }
}
