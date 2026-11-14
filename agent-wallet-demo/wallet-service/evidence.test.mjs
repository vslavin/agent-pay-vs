import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createSign } from 'node:crypto'
import { generateAgentKey, signRequest, thumbprint } from './tap.mjs'
import { generateUserKey, createOpenMandate, createClosedMandate, createMandateReceipt, createPaymentReceipt, orderOf, orderHash, sha256b64u, signJws, decodeJws, OPEN_TYP, toMicro } from './mandate.mjs'
import { verifyEvidence, mandateTerms, approvalTerms, termsHash, termsFromOpenMandate, normAmount, EVIDENCE_VERSION } from './evidence.mjs'
import { memoTopic, MEMO_TOPIC } from './payment.mjs'

const NOW = Date.now()
const ISS = 'https://id.example/realms/demo', AUD = 'demo-app'
const kc = generateKeyPairSync('rsa', { modulusLength: 2048 })
const kcJwk = { ...kc.publicKey.export({ format: 'jwk' }), kid: 'kc1', use: 'sig', alg: 'RS256' }
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
const idToken = (claims, key = kc.privateKey) => {
  const h = b64u({ alg: 'RS256', typ: 'JWT', kid: 'kc1' }), p = b64u({ iss: ISS, aud: AUD, iat: Math.floor(NOW / 1000), exp: Math.floor(NOW / 1000) + 300, ...claims })
  return `${h}.${p}.${createSign('RSA-SHA256').update(`${h}.${p}`).sign(key).toString('base64url')}`
}
const pad = (a) => '0x' + a.slice(2).padStart(64, '0')
const PAYER = '0x1111111111111111111111111111111111111111', PAYEE = '0x2222222222222222222222222222222222222222', TOKEN = '0x20c0000000000000000000006a37da5c996874be'

// A complete, honest bundle. `human` adds a per-purchase approval.
function build({ human = false, amount = '420', max = '500', budget = '1000', hours = 24 } = {}) {
  const user = generateUserKey(), agent = generateAgentKey(), store = generateUserKey()
  const merchantNames = { luxe: 'Luxe Atelier' }
  const sec = Math.floor(NOW / 1000)
  const open = createOpenMandate({ user, userSub: 'user-1', agent: { id: 'agt_1', publicJwk: agent.publicJwk }, constraints: { merchants: ['luxe'], merchantNames, maxPerPurchase: max, budget, currency: 'OUSD' }, ttlSeconds: hours * 3600, now: NOW - 60_000 })
  const order = { id: 'ord_0123456789ab', merchant: 'luxe', sku: 'LUX-001', item: 'Meridian 38', amount, currency: 'OUSD', status: 'paid', createdAt: new Date(NOW).toISOString(), txHash: '0x' + 'ab'.repeat(32) }
  const want = orderOf({ merchant: 'luxe', sku: 'LUX-001', amount })
  const closed = createClosedMandate({ agentKey: agent, openJws: open.jws, order: want, payee: PAYEE, now: NOW })
  const hdr = Object.fromEntries(Object.entries(signRequest({ privateJwk: agent.privateJwk, keyid: agent.keyid, authority: 'shop.example', path: '/shop/luxe/checkout', tag: 'agent-payer-auth', now: NOW })).map(([k, v]) => [k.toLowerCase(), v]))
  const closedHash = sha256b64u(closed.jws)
  const grantTerms = mandateTerms({ sub: 'user-1', agentId: 'agt_1', merchants: ['luxe'], maxPerPurchase: max, budget, hours })
  const bundle = {
    version: EVIDENCE_VERSION, order, mandates: { open: open.jws, closed: closed.jws },
    request: { authority: 'shop.example', path: '/shop/luxe/checkout', headers: hdr },
    receipts: {
      mandate: createMandateReceipt({ issuer: 'https://shop.example/shop/luxe', key: store, reference: closedHash, now: NOW }).jws,
      payment: createPaymentReceipt({ issuer: 'https://shop.example/shop/luxe', key: store, reference: closedHash, paymentId: order.id, txHash: order.txHash, now: NOW }).jws,
    },
    grant: { proof: { idToken: idToken({ sub: 'user-1', auth_time: sec - 60 - 20, nonce: termsHash(grantTerms) }) } },
    approval: null, chain: { token: TOKEN, payer: PAYER, payee: PAYEE, txHash: order.txHash },
    keys: { user: { sub: 'user-1', jwk: user.publicJwk }, agent: { id: 'agt_1', kid: agent.keyid, jwk: agent.publicJwk }, store: { username: 'luxe', kid: store.kid, jwk: store.publicJwk }, oidc: { issuer: ISS, audience: AUD, jwks: { keys: [kcJwk] } } },
  }
  if (human) {
    const approvalId = 'apr_0123456789ab', decided = sec - 5
    bundle.approval = { id: approvalId, createdAt: new Date(NOW - 30_000).toISOString(), decidedAt: new Date(decided * 1000).toISOString(),
      proof: { idToken: idToken({ sub: 'user-1', auth_time: decided - 10, nonce: termsHash(approvalTerms({ approvalId, orderHash: orderHash(want), mandateId: open.id })) }) } }
  }
  return { bundle, user, agent, store, open, closed, want }
}
const status = (r, name) => r.steps.find((s) => s.name === name)?.status
const clone = (b) => JSON.parse(JSON.stringify(b))

test('terms hashing is canonical: key order, duplicate stores and trailing zeros do not matter', () => {
  const a = mandateTerms({ sub: 'u', agentId: 'a', merchants: ['b', 'a', 'a'], maxPerPurchase: '150.00', budget: '300', hours: 24 })
  const b = mandateTerms({ sub: 'u', agentId: 'a', merchants: ['a', 'b'], maxPerPurchase: '150', budget: '300.000000', hours: 24 })
  assert.equal(termsHash(a), termsHash(b))
  assert.equal(normAmount('0.50'), '0.5')
  assert.notEqual(termsHash(a), termsHash({ ...a, budget: '301' }))
})

test('the terms can be rebuilt from the signed mandate alone', () => {
  const { open } = build({ max: '150.5', budget: '300' })
  assert.deepEqual(termsFromOpenMandate(open.payload), mandateTerms({ sub: 'user-1', agentId: 'agt_1', merchants: ['luxe'], maxPerPurchase: '150.5', budget: '300', hours: 24 }))
})

test('a complete autonomous bundle verifies, and the chain step is skipped until a receipt is supplied', () => {
  const { bundle } = build()
  const r = verifyEvidence(bundle)
  assert.equal(r.ok, true, JSON.stringify(r.steps.filter((s) => s.status === 'fail')))
  assert.equal(r.proven, true)
  assert.equal(status(r, 'mandate_grant_proof'), 'pass')
  assert.equal(status(r, 'approval_proof'), 'skip')
  assert.equal(status(r, 'chain'), 'skip')
})

test('a human-present bundle verifies, including the cart approval proof', () => {
  const r = verifyEvidence(build({ human: true }).bundle)
  assert.equal(r.ok, true, JSON.stringify(r.steps.filter((s) => s.status === 'fail')))
  assert.equal(status(r, 'approval_proof'), 'pass')
})

test('the chain step checks payer, payee, amount and memo from the transaction logs', () => {
  const { bundle } = build()
  const good = { status: 'success', logs: [{ address: TOKEN, topics: [MEMO_TOPIC, pad(PAYER), pad(PAYEE), memoTopic('ord_0123456789ab')], data: '0x' + toMicro('420').toString(16).padStart(64, '0') }] }
  assert.equal(status(verifyEvidence(bundle, { chainReceipt: good }), 'chain'), 'pass')
  assert.equal(status(verifyEvidence(bundle, { chainReceipt: { ...good, status: 'reverted' } }), 'chain'), 'fail')
  assert.equal(status(verifyEvidence(bundle, { chainReceipt: { status: 'success', logs: [] } }), 'chain'), 'fail')
})

test('altering the order after the fact is caught by the closed mandate and the receipts', () => {
  const { bundle } = build()
  const b = clone(bundle); b.order.amount = '4'
  const r = verifyEvidence(b)
  assert.equal(r.ok, false)
  assert.equal(status(r, 'closed_mandate'), 'fail')
  const c = clone(bundle); c.order.sku = 'LUX-002'
  assert.equal(status(verifyEvidence(c), 'closed_mandate'), 'fail')
})

test('a receipt signed by someone else, or pointing at another closed mandate, is caught', () => {
  const { bundle } = build()
  const forged = clone(bundle); forged.receipts.payment = createPaymentReceipt({ issuer: 'x', key: generateUserKey(), reference: sha256b64u(bundle.mandates.closed), paymentId: bundle.order.id, txHash: bundle.order.txHash }).jws
  assert.equal(status(verifyEvidence(forged), 'payment_receipt'), 'fail')
  const other = clone(bundle); other.mandates.closed = build().bundle.mandates.closed
  assert.equal(status(verifyEvidence(other), 'mandate_receipt'), 'fail')
})

test('a mandate signed by a key that is not the named user is caught', () => {
  const { bundle } = build()
  const b = clone(bundle); b.keys.user.jwk = generateUserKey().publicJwk
  assert.equal(status(verifyEvidence(b), 'open_mandate'), 'fail')
})

test('an order above the mandate limit, or at a store not on it, fails the limits step', () => {
  const big = build({ amount: '600', max: '500' })
  assert.equal(status(verifyEvidence(big.bundle), 'limits'), 'fail')
  const { bundle } = build(); const b = clone(bundle); b.order.merchant = 'someone-else'
  assert.equal(verifyEvidence(b).ok, false)
})

test('the agent request signature must verify with the agent key in the bundle', () => {
  const { bundle } = build()
  const b = clone(bundle); b.request.path = '/shop/luxe/other'
  assert.equal(status(verifyEvidence(b), 'agent_request'), 'fail')
  const c = clone(bundle); delete c.request
  assert.equal(status(verifyEvidence(c), 'agent_request'), 'fail')
})

test('the sign-in proof must be Keycloak-signed, for this user, bound to these terms, and fresh', () => {
  const { bundle } = build()
  const sec = Math.floor(NOW / 1000)
  const term = termsHash(termsFromOpenMandate(decodeJws(bundle.mandates.open).payload))
  const withToken = (claims, key) => { const b = clone(bundle); b.grant.proof.idToken = idToken({ sub: 'user-1', auth_time: sec - 80, nonce: term, ...claims }, key); return b }
  assert.equal(status(verifyEvidence(withToken({})), 'mandate_grant_proof'), 'pass')
  assert.equal(status(verifyEvidence(withToken({ nonce: 'something-else' })), 'mandate_grant_proof'), 'fail')   // not these terms
  assert.equal(status(verifyEvidence(withToken({ sub: 'user-2' })), 'mandate_grant_proof'), 'fail')             // someone else's sign-in
  assert.equal(status(verifyEvidence(withToken({ auth_time: sec - 3600 })), 'mandate_grant_proof'), 'fail')     // stale
  assert.equal(status(verifyEvidence(withToken({}, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey)), 'mandate_grant_proof'), 'fail')   // forged
  const none = clone(bundle); delete none.grant
  assert.equal(status(verifyEvidence(none), 'mandate_grant_proof'), 'fail')
})

test('a mandate changed after approval no longer matches the signed-in terms', () => {
  const a = build({ max: '500' }), b = build({ max: '500' })
  // keep a's evidence but swap in a mandate with different limits, correctly re-signed by the same user key
  const d = decodeJws(a.bundle.mandates.open).payload
  const raised = signJws({ ...d, constraints: d.constraints.map((c) => (c.type === 'payment.amount_range' ? { ...c, max: 900_000_000 } : c)) }, a.user.privateJwk, a.user.kid, OPEN_TYP)
  const bundle = clone(a.bundle); bundle.mandates.open = raised
  const r = verifyEvidence(bundle)
  assert.equal(status(r, 'mandate_grant_proof'), 'fail')   // the user never signed in for these limits
  assert.ok(b)
})

test('the bundle can be checked against an independently fetched Keycloak key set', () => {
  const { bundle } = build()
  const other = { keys: [{ ...kcJwk, n: generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' }).n }] }
  assert.equal(status(verifyEvidence(bundle, { oidcJwks: other }), 'mandate_grant_proof'), 'fail')
  assert.equal(status(verifyEvidence(bundle, { oidcJwks: { keys: [kcJwk] } }), 'mandate_grant_proof'), 'pass')
})

test('a mandate created in development mode verifies but is flagged as unproven', () => {
  const { bundle } = build()
  const b = clone(bundle); b.grant = { proof: { mode: 'dev-unproven' } }
  const r = verifyEvidence(b)
  assert.equal(r.ok, true)
  assert.equal(r.proven, false)
  assert.equal(status(r, 'mandate_grant_proof'), 'warn')
})

test('garbage bundles fail cleanly', () => {
  for (const b of [null, {}, { version: 'x' }, { version: EVIDENCE_VERSION }]) assert.equal(verifyEvidence(b).ok, false)
})
