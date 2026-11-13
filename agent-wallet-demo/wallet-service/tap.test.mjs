import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateAgentKey, signRequest, verifyRequest, thumbprint } from './tap.mjs'

const agent = generateAgentKey()
const other = generateAgentKey()
const registry = { [agent.keyid]: agent.publicJwk, [other.keyid]: other.publicJwk }
const lookupKey = (id) => registry[id] ?? null
const lower = (h) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]))
const sign = (over = {}) => signRequest({ privateJwk: agent.privateJwk, keyid: agent.keyid, authority: 'shop.example', path: '/checkout', tag: 'agent-payer-auth', ...over })
const check = (headers, over = {}) => verifyRequest({ headers: lower(headers), authority: 'shop.example', path: '/checkout', lookupKey, seenNonces: new Map(), ...over })

test('key id is the RFC 7638 thumbprint of the public key', () => {
  assert.equal(agent.keyid, thumbprint(agent.publicJwk))
  assert.equal(agent.publicJwk.crv, 'Ed25519')
  assert.equal(agent.publicJwk.d, undefined)
})

test('a signed request verifies against the registry', () => {
  const r = check(sign())
  assert.equal(r.ok, true)
  assert.equal(r.keyid, agent.keyid)
  assert.equal(r.tag, 'agent-payer-auth')
})

test('signature headers carry the TAP parameters', () => {
  const h = sign({ tag: 'agent-browser-auth' })
  assert.match(h['Signature-Input'], /^sig2=\("@authority" "@path"\);created=\d+;keyid="[\w-]+";alg="Ed25519";expires=\d+;nonce="[^"]+";tag="agent-browser-auth"$/)
  assert.match(h.Signature, /^sig2=:[A-Za-z0-9+/]+=*:$/)
})

test('a different authority or path invalidates the signature', () => {
  const h = sign()
  assert.equal(check(h, { authority: 'evil.example' }).reason, 'bad_signature')
  assert.equal(check(h, { path: '/other' }).reason, 'bad_signature')
})

test('a key not in the registry is rejected', () => {
  const stranger = generateAgentKey()
  const h = signRequest({ privateJwk: stranger.privateJwk, keyid: stranger.keyid, authority: 'shop.example', path: '/checkout', tag: 'agent-payer-auth' })
  assert.equal(check(h).reason, 'unknown_key')
})

test('claiming another agent\'s key id fails the signature check', () => {
  const h = signRequest({ privateJwk: agent.privateJwk, keyid: other.keyid, authority: 'shop.example', path: '/checkout', tag: 'agent-payer-auth' })
  assert.equal(check(h).reason, 'bad_signature')
})

test('a tampered signature is rejected', () => {
  const h = sign()
  const bad = { ...h, Signature: h.Signature.replace(/^(sig2=:)(.)/, (m, head, c) => head + (c === 'A' ? 'B' : 'A')) }
  assert.equal(check(bad).reason, 'bad_signature')
})

test('an expired signature is rejected, a future one too', () => {
  const now = Date.now()
  assert.equal(check(sign({ now: now - 10 * 60 * 1000, ttl: 480 })).reason, 'expired')
  assert.equal(check(sign({ now: now + 5 * 60 * 1000 })).reason, 'created_in_future')
})

test('a nonce cannot be replayed', () => {
  const seenNonces = new Map()
  const h = sign()
  assert.equal(check(h, { seenNonces }).ok, true)
  assert.equal(check(h, { seenNonces }).reason, 'replayed_nonce')
})

test('a failed check does not burn the nonce', () => {
  const seenNonces = new Map()
  const h = sign()
  assert.equal(check(h, { seenNonces, authority: 'evil.example' }).ok, false)
  assert.equal(seenNonces.size, 0)
  assert.equal(check(h, { seenNonces }).ok, true)
})

test('only the two TAP tags are allowed', () => {
  assert.throws(() => sign({ tag: 'anything' }), /tag must be one of/)
  const h = sign()
  const forged = { ...h, 'Signature-Input': h['Signature-Input'].replace('agent-payer-auth', 'other') }
  assert.equal(check(forged).reason, 'bad_tag')
})

test('missing or malformed headers are rejected', () => {
  assert.equal(check({}).reason, 'missing_signature')
  assert.equal(check({ 'Signature-Input': 'garbage', Signature: 'garbage' }).reason, 'malformed_signature')
  const h = sign()
  assert.equal(check({ ...h, 'Signature-Input': h['Signature-Input'].replace('"@path"', '') }).reason, 'missing_components')
})

test('lifetimes over 8 minutes cannot be signed', () => {
  assert.throws(() => sign({ ttl: 481 }), /ttl must be/)
})
