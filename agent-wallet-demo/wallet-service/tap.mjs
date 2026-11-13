import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto'

// TAP-style agent identity: RFC 9421 HTTP Message Signatures with Ed25519 keys.
// Modelled on Visa's published Trusted Agent Protocol spec (covered components,
// created/expires/nonce/tag/alg/keyid parameters, 8-minute window). Visa does not
// run a developer key directory, so keys are registered with this demo instead.

export const TAGS = ['agent-browser-auth', 'agent-payer-auth']
export const WINDOW_SECONDS = 8 * 60
const LABEL = 'sig2'
const SKEW_SECONDS = 60

export function thumbprint(jwk) {
  return createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('base64url')
}

export function generateAgentKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicJwk = publicKey.export({ format: 'jwk' })
  return { keyid: thumbprint(publicJwk), publicJwk, privateJwk: privateKey.export({ format: 'jwk' }) }
}

const sigParams = ({ keyid, created, expires, nonce, tag }) =>
  `("@authority" "@path");created=${created};keyid="${keyid}";alg="Ed25519";expires=${expires};nonce="${nonce}";tag="${tag}"`

const signatureBase = (authority, path, params) =>
  `"@authority": ${authority}\n"@path": ${path}\n"@signature-params": ${params}`

export function signRequest({ privateJwk, keyid, authority, path, tag, now = Date.now(), ttl = 300, nonce = randomBytes(24).toString('base64') }) {
  if (!TAGS.includes(tag)) throw new Error(`tag must be one of ${TAGS.join(', ')}`)
  if (ttl <= 0 || ttl > WINDOW_SECONDS) throw new Error(`ttl must be between 1 and ${WINDOW_SECONDS} seconds`)
  const created = Math.floor(now / 1000)
  const params = sigParams({ keyid, created, expires: created + ttl, nonce, tag })
  const signature = sign(null, Buffer.from(signatureBase(authority, path, params)), createPrivateKey({ key: privateJwk, format: 'jwk' }))
  return { 'Signature-Input': `${LABEL}=${params}`, Signature: `${LABEL}=:${signature.toString('base64')}:` }
}

function parseParams(text) {
  const out = {}
  for (const m of text.matchAll(/;\s*([a-z0-9_-]+)=(?:"([^"]*)"|([^;\s]+))/gi)) out[m[1].toLowerCase()] = m[2] ?? m[3]
  return out
}

// headers: { 'signature-input', 'signature' } (lower-case names). lookupKey(keyid) returns a public JWK or null.
// seenNonces: a Map shared across calls, used to reject replays.
export function verifyRequest({ headers, authority, path, lookupKey, seenNonces, now = Date.now() }) {
  const input = headers['signature-input']
  const sigHeader = headers.signature
  if (!input || !sigHeader) return { ok: false, reason: 'missing_signature' }
  const head = input.match(/^([A-Za-z][\w-]*)=\(([^)]*)\)(.*)$/s)
  const sig = sigHeader.match(/^([A-Za-z][\w-]*)=:([A-Za-z0-9+/]+={0,2}):$/)
  if (!head || !sig || head[1] !== sig[1]) return { ok: false, reason: 'malformed_signature' }

  const covered = [...head[2].matchAll(/"([^"]+)"/g)].map((m) => m[1])
  if (!covered.includes('@authority') || !covered.includes('@path')) return { ok: false, reason: 'missing_components' }
  const p = parseParams(head[3])
  for (const name of ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag']) {
    if (p[name] == null) return { ok: false, reason: `missing_param_${name}` }
  }
  if (!TAGS.includes(p.tag)) return { ok: false, reason: 'bad_tag' }
  if (p.alg.toLowerCase() !== 'ed25519') return { ok: false, reason: 'bad_alg' }

  const nowSec = Math.floor(now / 1000)
  const created = Number(p.created)
  const expires = Number(p.expires)
  if (!Number.isInteger(created) || !Number.isInteger(expires)) return { ok: false, reason: 'malformed_signature' }
  if (created > nowSec + SKEW_SECONDS) return { ok: false, reason: 'created_in_future' }
  if (nowSec - created > WINDOW_SECONDS || expires <= nowSec) return { ok: false, reason: 'expired' }
  if (expires - created > WINDOW_SECONDS) return { ok: false, reason: 'window_too_long' }

  for (const [n, until] of seenNonces) if (until <= nowSec) seenNonces.delete(n)
  if (seenNonces.has(p.nonce)) return { ok: false, reason: 'replayed_nonce' }

  const jwk = lookupKey(p.keyid)
  if (!jwk) return { ok: false, reason: 'unknown_key' }
  const base = signatureBase(authority, path, head[0].slice(head[1].length + 1))
  const good = verify(null, Buffer.from(base), createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(sig[2], 'base64'))
  if (!good) return { ok: false, reason: 'bad_signature' }

  seenNonces.set(p.nonce, created + WINDOW_SECONDS)
  return { ok: true, keyid: p.keyid, tag: p.tag, created, expires }
}
