import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createSign, createHmac } from 'node:crypto'
import { verifyIdToken, decodeIdToken } from './oidc.mjs'

const NOW = Date.now()
const ISS = 'https://id.example/realms/demo'
const AUD = 'demo-app'
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }
const jwks = { keys: [jwk] }
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
function mint(over = {}, { key = privateKey, header = {} } = {}) {
  const h = b64u({ alg: 'RS256', typ: 'JWT', kid: 'k1', ...header })
  const p = b64u({ iss: ISS, aud: AUD, sub: 'u1', iat: Math.floor(NOW / 1000), exp: Math.floor(NOW / 1000) + 300, auth_time: Math.floor(NOW / 1000), nonce: 'n1', ...over })
  const sig = createSign('RSA-SHA256').update(`${h}.${p}`).sign(key).toString('base64url')
  return `${h}.${p}.${sig}`
}
const check = (token) => verifyIdToken(token, { jwks, issuer: ISS, audience: AUD, now: NOW })

test('a token signed by the realm key, with the right issuer and audience, verifies', () => {
  const r = check(mint())
  assert.equal(r.ok, true)
  assert.equal(r.claims.nonce, 'n1')
})

test('a token signed by another key, or tampered, is refused', () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 })
  assert.equal(check(mint({}, { key: other.privateKey })).reason, 'bad signature')
  const parts = mint().split('.')
  const tampered = [parts[0], b64u({ iss: ISS, aud: AUD, sub: 'someone-else', iat: Math.floor(NOW / 1000), exp: Math.floor(NOW / 1000) + 300 }), parts[2]].join('.')
  assert.equal(check(tampered).reason, 'bad signature')
})

test('wrong issuer, wrong audience, expired and future tokens are refused', () => {
  assert.equal(check(mint({ iss: 'https://evil.example/realms/demo' })).reason, 'wrong issuer')
  assert.equal(check(mint({ aud: 'other-app' })).reason, 'wrong audience')
  assert.equal(check(mint({ aud: ['x', AUD] })).ok, true)
  assert.equal(check(mint({ exp: Math.floor(NOW / 1000) - 10 })).reason, 'token expired')
  assert.equal(check(mint({ iat: Math.floor(NOW / 1000) + 3600 })).reason, 'token issued in the future')
})

test('unknown key ids and unsupported algorithms are refused', () => {
  assert.equal(check(mint({}, { header: { kid: 'nope' } })).reason, 'unknown signing key')
  assert.match(check(mint({}, { header: { alg: 'none' } })).reason, /unsupported algorithm/)
  // HMAC confusion: sign with the public key as the secret and claim HS256
  const h = b64u({ alg: 'HS256', typ: 'JWT', kid: 'k1' }), p = b64u({ iss: ISS, aud: AUD, exp: Math.floor(NOW / 1000) + 300, iat: Math.floor(NOW / 1000) })
  const sig = createHmac('sha256', publicKey.export({ type: 'spki', format: 'pem' })).update(`${h}.${p}`).digest('base64url')
  assert.match(check(`${h}.${p}.${sig}`).reason, /unsupported algorithm/)
})

test('garbage is refused without throwing', () => {
  for (const t of ['', 'a.b', 'a.b.c.d', null, undefined, 42, 'x'.repeat(30_000)]) assert.equal(check(t).ok, false)
  assert.equal(decodeIdToken('a.b.c'), null)
})
