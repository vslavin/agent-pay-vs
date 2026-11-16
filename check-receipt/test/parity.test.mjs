import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { verifyEvidence } from '../../agent-wallet-demo/wallet-service/evidence.mjs'
import { generateUserKey, createClosedMandate, orderOf } from '../../agent-wallet-demo/wallet-service/mandate.mjs'
import { termsHash, mandateTerms } from '../../agent-wallet-demo/wallet-service/evidence.mjs'
import { verifyBundle } from '../verify.js'
import { build, makeKeycloak, goodChain, pad, PAYEE, TOKEN, NOW } from './fixtures.mjs'

// The page's verifier and the wallet service's must agree on every bundle, honest or tampered: same verdict, same steps.
const clone = (b) => JSON.parse(JSON.stringify(b))
const flip = (jws) => { const i = jws.lastIndexOf('.') + 3; return jws.slice(0, i) + (jws[i] === 'A' ? 'B' : 'A') + jws.slice(i + 1) }

async function same(label, bundle, opts = {}) {
  const want = verifyEvidence(bundle, opts)
  const got = await verifyBundle(bundle, opts)
  assert.deepEqual(got.steps.map((s) => [s.name, s.status]), want.steps.map((s) => [s.name, s.status]), `${label}: steps differ\n got ${JSON.stringify(got.steps)}\nwant ${JSON.stringify(want.steps)}`)
  assert.equal(got.ok, want.ok, `${label}: ok`)
  assert.equal(got.proven, want.proven, `${label}: proven`)
  return got
}

test('honest bundles agree: autonomous, human-present, with and without a chain receipt', async () => {
  const a = build(), h = build({ human: true })
  assert.equal((await same('autonomous', a.bundle)).ok, true)
  assert.equal((await same('human', h.bundle)).proven, true)
  const c = await same('chain', h.bundle, { chainReceipt: goodChain() })
  assert.equal(c.steps.find((s) => s.name === 'chain').status, 'pass')
})

test('the committed example bundle verifies, including its chain receipt', async () => {
  const b = JSON.parse(readFileSync(new URL('../example-bundle.json', import.meta.url), 'utf8'))
  const r = await same('example', b, { chainReceipt: b._example.chainReceipt })
  assert.equal(r.proven, true, JSON.stringify(r.steps.filter((s) => s.status !== 'pass')))
})

test('tampered bundles get the same verdict from both verifiers', async () => {
  const h = build({ human: true })
  const other = generateUserKey()
  const cases = {
    'price lowered': (b) => { b.order.amount = '1' },
    'different store': (b) => { b.order.merchant = 'vsemporium' },
    'different item': (b) => { b.order.sku = 'LUX-002' },
    'open mandate signature flipped': (b) => { b.mandates.open = flip(b.mandates.open) },
    'closed mandate signature flipped': (b) => { b.mandates.closed = flip(b.mandates.closed) },
    "someone else's user key": (b) => { b.keys.user.jwk = other.publicJwk },
    "someone else's store key": (b) => { b.keys.store.jwk = other.publicJwk },
    'payment receipt removed': (b) => { b.receipts.payment = null },
    'mandate receipt flipped': (b) => { b.receipts.mandate = flip(b.receipts.mandate) },
    'wrong transaction': (b) => { b.order.txHash = '0x' + 'cd'.repeat(32) },
    'agent request path changed': (b) => { b.request.path = '/shop/other/checkout' },
    'agent request missing': (b) => { b.request = null },
    'agent key swapped': (b) => { b.keys.agent.jwk = other.publicJwk },
    'agent kid wrong': (b) => { b.keys.agent.kid = 'nope' },
    'sign-in proof removed': (b) => { b.grant = null },
    'sign-in proof garbage': (b) => { b.grant.proof.idToken = 'not.a.token' },
    'keycloak keys replaced': (b) => { b.keys.oidc.jwks = { keys: [makeKeycloak().jwk] } },
    'keycloak issuer changed': (b) => { b.keys.oidc.issuer = 'https://evil.example/realms/x' },
    'keycloak audience changed': (b) => { b.keys.oidc.audience = 'other-app' },
    'approval id changed (nonce mismatch)': (b) => { b.approval.id = 'apr_ffffffffffff' },
    'approval decided much later (stale sign-in)': (b) => { b.approval.decidedAt = new Date(NOW + 3600_000).toISOString() },
    'order created after the mandate expired': (b) => { b.order.createdAt = new Date(NOW + 3 * 86400_000).toISOString() },
    'version changed': (b) => { b.version = 'agent-pay-evidence/2' },
    'user sub changed': (b) => { b.keys.user.sub = 'someone-else' },
  }
  for (const [label, mutate] of Object.entries(cases)) {
    const b = clone(h.bundle); mutate(b)
    const r = await same(label, b)
    assert.equal(r.ok, false, `${label}: expected a failure`)
  }
})

test('an unpaid quote needs no payment receipt, in both', async () => {
  const b = clone(build().bundle)
  b.order.status = 'payment_required'; b.receipts.payment = null; b.order.txHash = null
  const r = await same('unpaid quote', b)
  assert.equal(r.ok, true)
  assert.equal(r.steps.find((s) => s.name === 'payment_receipt').status, 'skip')
})

test('known limit, same in both: a bundle with no approval reads as an autonomous purchase', async () => {
  // The bundle does not say which purchase mode the store ran. Dropping the approval therefore cannot be told apart from
  // a purchase made at an autonomous store; the page says so next to the step.
  const b = clone(build({ human: true }).bundle)
  b.approval = null
  const r = await same('approval dropped', b)
  assert.equal(r.ok, true)
  assert.equal(r.steps.find((s) => s.name === 'approval_proof').status, 'skip')
})

test('a development-mode grant is a warning, not a pass, in both', async () => {
  const b = clone(build().bundle)
  b.grant = { proof: { mode: 'dev-unproven' } }
  const r = await same('dev-unproven', b)
  assert.equal(r.ok, true)
  assert.equal(r.proven, false)
})

test('structurally broken input fails the same way', async () => {
  for (const b of [null, undefined, {}, [], { version: 'x' }, 'text', 42]) await same(String(b), b)
})

test('a closed mandate signed by the real agent for a different order is caught by both', async () => {
  const h = build()
  const b = clone(h.bundle)
  const wrong = orderOf({ merchant: 'luxe', sku: 'LUX-009', amount: '420' })
  b.mandates.closed = createClosedMandate({ agentKey: h.agent, openJws: b.mandates.open, order: wrong, payee: PAYEE, now: NOW }).jws
  assert.equal((await same('different order', b)).ok, false)
})

test('a sign-in bound to different terms is caught by both', async () => {
  const h = build()
  const b = clone(h.bundle)
  b.grant.proof.idToken = h.kc.idToken({ sub: 'user-1', auth_time: Math.floor(NOW / 1000) - 80, nonce: termsHash(mandateTerms({ sub: 'user-1', agentId: 'agt_1', merchants: ['luxe'], maxPerPurchase: '500', budget: '9999', hours: 24 })) })
  const r = await same('other terms', b)
  assert.match(r.steps.find((s) => s.name === 'mandate_grant_proof').detail, /nonce mismatch/)
})

test('Keycloak keys supplied separately override the bundle’s, in both', async () => {
  const h = build({ human: true })
  assert.equal((await same('override good', h.bundle, { oidcJwks: { keys: [h.kc.jwk] } })).ok, true)
  assert.equal((await same('override bad', h.bundle, { oidcJwks: { keys: [makeKeycloak().jwk] } })).ok, false)
})

test('chain receipts: reverted, empty, wrong payee, wrong amount, wrong memo', async () => {
  const h = build()
  const good = goodChain()
  const log = good.logs[0]
  const variants = {
    reverted: { ...good, status: 'reverted' },
    empty: { status: 'success', logs: [] },
    'not found': { status: 'not found', logs: [] },
    'wrong payee': { status: 'success', logs: [{ ...log, topics: [log.topics[0], log.topics[1], pad('0x3333333333333333333333333333333333333333'), log.topics[3]] }] },
    'wrong amount': goodChain('ord_0123456789ab', '419'),
    'wrong memo': goodChain('ord_ffffffffffff'),
    'wrong token': { status: 'success', logs: [{ ...log, address: '0x0000000000000000000000000000000000000001' }] },
  }
  for (const [label, c] of Object.entries(variants)) assert.equal((await same(label, h.bundle, { chainReceipt: c })).ok, false, label)
  assert.equal(TOKEN.length, 42)
})
