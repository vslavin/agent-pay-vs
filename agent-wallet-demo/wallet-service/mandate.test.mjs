import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateAgentKey, signRequest } from './tap.mjs'
import {
  generateUserKey, createOpenMandate, createClosedMandate, evaluateCheckout, orderOf, orderHash, canonicalJson,
  toMicro, fromMicro, signJws, decodeJws, verifyJws, OPEN_TYP, OPEN_VCT, CLOSED_VCT, MANDATE_RECEIPT_TYP, PAYMENT_RECEIPT_TYP,
  createMandateReceipt, createPaymentReceipt, mandateErrorCode, sha256b64u,
} from './mandate.mjs'

const NOW = Date.now()
const MERCHANT = { username: 'vsemporium', address: '0xC057A1fA0410AAFd7251C19eB00Db4722ce0bc33' }
const AUTHORITY = 'shop.example'
const PATH = '/shop/vsemporium/checkout'

// A world with one user, two agents, and a store.
function world(over = {}) {
  const user = generateUserKey()
  const agent = generateAgentKey()
  const other = generateAgentKey()
  const constraints = { merchants: ['vsemporium'], maxPerPurchase: '150', budget: '300', ...over.constraints }
  const open = createOpenMandate({ user, userSub: 'user-1', agent: { id: 'agt_1', publicJwk: agent.publicJwk }, constraints, ttlSeconds: over.ttl ?? 3600, now: over.openNow ?? NOW })
  const records = new Map([[open.id, { status: over.status ?? 'active' }]])
  const spent = new Map([[open.id, toMicro(over.spent ?? '0')]])
  const agents = new Map([[agent.keyid, agent.publicJwk], [other.keyid, other.publicJwk]])
  const lookups = {
    agentPublicJwk: (id) => agents.get(id) ?? null,
    userPublicJwk: (sub) => (sub === 'user-1' ? user.publicJwk : null),
    mandateRecord: (id) => records.get(id) ?? null,
    spentMicro: (id) => spent.get(id) ?? 0n,
    seenNonces: new Map(), usedClosed: new Set(),
  }
  return { user, agent, other, open, lookups, records }
}
const ORDER = orderOf({ merchant: 'vsemporium', sku: 'VSE-001', amount: '89' })

function attempt(w, over = {}) {
  const order = over.order ?? ORDER
  const signer = over.signer ?? w.agent
  const headers = over.headers ?? Object.fromEntries(Object.entries(signRequest({ privateJwk: signer.privateJwk, keyid: signer.keyid, authority: AUTHORITY, path: PATH, tag: over.tag ?? 'agent-payer-auth', now: NOW })).map(([k, v]) => [k.toLowerCase(), v]))
  const closed = 'closed' in over ? over.closed : createClosedMandate({ agentKey: w.agent, openJws: w.open.jws, order, payee: MERCHANT.address, now: NOW }).jws
  const open = 'open' in over ? over.open : w.open.jws
  return evaluateCheckout({ now: NOW, request: { headers, authority: AUTHORITY, path: PATH }, order, mandates: { open, closed }, merchant: MERCHANT, policy: over.policy, lookups: w.lookups })
}
const failsWith = (r, code, status) => { assert.equal(r.ok, false); assert.equal(r.code, code); assert.equal(r.status, status) }

test('a valid signed request with open and closed mandates is authorized', () => {
  const r = attempt(world())
  assert.equal(r.ok, true)
  assert.deepEqual(r.checks.map((c) => c.name), ['agent_signature', 'open_mandate', 'mandate_bound_to_agent', 'mandate_active', 'payee_allowed', 'amount_in_range', 'budget_available', 'closed_mandate', 'purchase_mode'])
  assert.ok(r.checks.every((c) => c.ok))
  assert.equal(r.context.amountMicro, 89_000_000n)
})

test('identity failures are 401: missing, unknown key, wrong tag', () => {
  const w = world()
  failsWith(attempt(w, { headers: {} }), 'agent_signature', 401)
  const stranger = generateAgentKey()
  failsWith(attempt(world(), { signer: stranger }), 'agent_signature', 401)
  failsWith(attempt(world(), { tag: 'agent-browser-auth' }), 'agent_signature', 401)
})

test('a replayed signed request is rejected', () => {
  const w = world()
  const headers = Object.fromEntries(Object.entries(signRequest({ privateJwk: w.agent.privateJwk, keyid: w.agent.keyid, authority: AUTHORITY, path: PATH, tag: 'agent-payer-auth', now: NOW })).map(([k, v]) => [k.toLowerCase(), v]))
  assert.equal(attempt(w, { headers }).ok, true)
  failsWith(attempt(w, { headers }), 'agent_signature', 401)
})

test('an agent with no open mandate has no authority', () => {
  failsWith(attempt(world(), { open: undefined }), 'open_mandate', 403)
  failsWith(attempt(world(), { open: 'garbage' }), 'open_mandate', 403)
})

test('a mandate from an unknown user, or tampered, is rejected', () => {
  const w = world()
  const forger = generateUserKey()
  const d = decodeJws(w.open.jws)
  const forged = signJws({ ...d.payload, iss: 'user-2' }, forger.privateJwk, forger.kid, OPEN_TYP)
  failsWith(attempt(w, { open: forged }), 'open_mandate', 403)
  const bigger = signJws({ ...d.payload, constraints: d.payload.constraints.map((c) => (c.type === 'payment.amount_range' ? { ...c, max: 99_999_000_000 } : c)) }, forger.privateJwk, w.user.kid, OPEN_TYP)
  failsWith(attempt(w, { open: bigger }), 'open_mandate', 403)
  const parts = w.open.jws.split('.')
  const tampered = [parts[0], Buffer.from(JSON.stringify({ ...d.payload, exp: d.payload.exp + 99999 })).toString('base64url'), parts[2]].join('.')
  failsWith(attempt(w, { open: tampered }), 'open_mandate', 403)
})

test('a mandate issued to a different agent cannot be used', () => {
  const w = world()
  failsWith(attempt(w, { signer: w.other }), 'mandate_bound_to_agent', 403)
})

test('revoked, unknown and expired mandates are refused', () => {
  failsWith(attempt(world({ status: 'revoked' })), 'mandate_active', 403)
  const w = world(); w.records.clear()
  failsWith(attempt(w), 'mandate_active', 403)
  failsWith(attempt(world({ ttl: 60, openNow: NOW - 3_600_000 })), 'mandate_active', 403)
})

test('the merchant must be on the allowed list', () => {
  failsWith(attempt(world({ constraints: { merchants: ['someone-else'] } })), 'payee_allowed', 403)
})

test('the per-purchase limit is enforced', () => {
  const w = world({ constraints: { maxPerPurchase: '80' } })
  failsWith(attempt(w), 'amount_in_range', 403)
  assert.equal(attempt(world({ constraints: { maxPerPurchase: '89' } })).ok, true)
})

test('the total budget is enforced, counting what is already spent', () => {
  failsWith(attempt(world({ constraints: { budget: '100' }, spent: '20' })), 'budget_available', 403)
  assert.equal(attempt(world({ constraints: { budget: '100' }, spent: '11' })).ok, true)
  const r = attempt(world({ constraints: { budget: '100' }, spent: '12' }))
  failsWith(r, 'budget_available', 403)
})

test('the closed mandate must exist, be signed by the agent, and match the open mandate', () => {
  const w = world()
  failsWith(attempt(w, { closed: undefined }), 'closed_mandate', 403)
  const forged = createClosedMandate({ agentKey: w.other, openJws: w.open.jws, order: ORDER, payee: MERCHANT.address, now: NOW }).jws
  failsWith(attempt(world(), { closed: forged }), 'closed_mandate', 403)
  const w2 = world()
  const otherOpen = createOpenMandate({ user: w2.user, userSub: 'user-1', agent: { id: 'agt_1', publicJwk: w2.agent.publicJwk }, constraints: { merchants: ['vsemporium'], maxPerPurchase: '150', budget: '300' }, ttlSeconds: 3600, now: NOW })
  const mismatched = createClosedMandate({ agentKey: w2.agent, openJws: otherOpen.jws, order: ORDER, payee: MERCHANT.address, now: NOW }).jws
  failsWith(attempt(w2, { closed: mismatched }), 'closed_mandate', 403)
})

test('the closed mandate is bound to the exact order and payee', () => {
  const w = world()
  const cheaper = orderOf({ merchant: 'vsemporium', sku: 'VSE-001', amount: '10' })
  failsWith(attempt(w, { closed: createClosedMandate({ agentKey: w.agent, openJws: w.open.jws, order: cheaper, payee: MERCHANT.address, now: NOW }).jws }), 'closed_mandate', 403)
  const w2 = world()
  failsWith(attempt(w2, { closed: createClosedMandate({ agentKey: w2.agent, openJws: w2.open.jws, order: ORDER, payee: '0x0000000000000000000000000000000000000001', now: NOW }).jws }), 'closed_mandate', 403)
})

test('an old closed mandate is outside its window', () => {
  const w = world()
  failsWith(attempt(w, { closed: createClosedMandate({ agentKey: w.agent, openJws: w.open.jws, order: ORDER, payee: MERCHANT.address, now: NOW - 3_600_000 }).jws }), 'closed_mandate', 403)
})

test('a closed mandate cannot be used twice', () => {
  const w = world()
  const closed = createClosedMandate({ agentKey: w.agent, openJws: w.open.jws, order: ORDER, payee: MERCHANT.address, now: NOW })
  assert.equal(attempt(w, { closed: closed.jws }).ok, true)
  w.lookups.usedClosed.add(closed.payload.jti)
  // a fresh request signature passes the identity check, but the closed mandate itself is spent
  failsWith(attempt(w, { closed: closed.jws }), 'closed_mandate', 403)
})

test('a store that demands a human refuses purely autonomous purchases', () => {
  const r = attempt(world(), { policy: { mode: 'human_present' } })
  failsWith(r, 'purchase_mode', 403)
  assert.equal(r.context.needsApproval, true)
})

test('human-present: an approval for this exact order and mandate lets the purchase through', () => {
  const w = world()
  const approvals = new Map()
  w.lookups.approvalFor = (hash, mandateId) => approvals.get(`${hash}|${mandateId}`) ?? null
  const key = `${orderHash(ORDER)}|${w.open.id}`
  const policy = { mode: 'human_present' }
  failsWith(attempt(w, { policy }), 'purchase_mode', 403)          // no approval yet
  approvals.set(key, { id: 'apr_1', status: 'pending' })
  const waiting = attempt(w, { policy })
  failsWith(waiting, 'purchase_mode', 403)
  assert.equal(waiting.context.needsApproval, undefined)            // already open: do not open another
  assert.equal(waiting.context.approvalId, 'apr_1')
  approvals.set(key, { id: 'apr_1', status: 'rejected' })
  failsWith(attempt(w, { policy }), 'purchase_mode', 403)
  approvals.set(key, { id: 'apr_1', status: 'approved' })
  const ok = attempt(w, { policy })
  assert.equal(ok.ok, true)
  assert.equal(ok.context.approvalId, 'apr_1')
})

test('human-present: approval of a different order does not carry over', () => {
  const w = world()
  const other = orderOf({ merchant: 'vsemporium', sku: 'VSE-002', amount: '89' })
  w.lookups.approvalFor = (hash) => (hash === orderHash(other) ? { id: 'apr_x', status: 'approved' } : null)
  failsWith(attempt(w, { policy: { mode: 'human_present' } }), 'purchase_mode', 403)
})

test('human-present: an approval held by an open quote cannot be spent again', () => {
  const w = world()
  w.lookups.approvalFor = () => ({ id: 'apr_1', status: 'reserved', orderId: 'ord_1' })
  const r = attempt(w, { policy: { mode: 'human_present' } })
  failsWith(r, 'purchase_mode', 403)
  assert.match(r.checks.find((c) => !c.ok).detail, /already has an open quote \(ord_1\)/)
  assert.equal(r.context.needsApproval, undefined)   // do not open a second approval either
})

test('an unknown purchase mode fails closed', () => {
  failsWith(attempt(world(), { policy: { mode: 'whatever' } }), 'purchase_mode', 403)
})

test('mandates use the AP2 claim shapes: typed constraint array, integer minor units, closed mandate fields', () => {
  const w = world({ constraints: { merchants: ['vsemporium'], merchantNames: { vsemporium: 'Vads' } } })
  const open = decodeJws(w.open.jws).payload
  assert.equal(open.vct, OPEN_VCT)
  assert.ok(Array.isArray(open.constraints))
  assert.deepEqual(open.constraints.find((c) => c.type === 'payment.allowed_payees').allowed, [{ id: 'vsemporium', name: 'Vads' }])
  assert.deepEqual(open.constraints.find((c) => c.type === 'payment.amount_range'), { type: 'payment.amount_range', currency: 'OUSD', min: 0, max: 150_000_000 })
  assert.deepEqual(open.constraints.find((c) => c.type === 'payment.budget'), { type: 'payment.budget', currency: 'OUSD', max: 300_000_000 })
  const closed = decodeJws(createClosedMandate({ agentKey: w.agent, openJws: w.open.jws, order: ORDER, payee: MERCHANT.address, now: NOW }).jws).payload
  assert.equal(closed.vct, CLOSED_VCT)
  assert.equal(closed.transaction_id, orderHash(ORDER))
  assert.deepEqual(closed.payment_amount, { amount: 89_000_000, currency: 'OUSD' })
  assert.deepEqual(closed.payee, { id: 'vsemporium', address: MERCHANT.address })
})

test('a constraint type the store does not know fails the evaluation', () => {
  const w = world()
  const d = decodeJws(w.open.jws)
  const open = signJws({ ...d.payload, constraints: [...d.payload.constraints, { type: 'payment.agent_recurrence', frequency: 'WEEKLY' }] }, w.user.privateJwk, w.user.kid, OPEN_TYP)
  failsWith(attempt(w, { open }), 'constraints_understood', 403)
})

test('an open mandate or closed mandate with the wrong vct is refused', () => {
  const w = world()
  const d = decodeJws(w.open.jws)
  failsWith(attempt(w, { open: signJws({ ...d.payload, vct: 'mandate.open.1' }, w.user.privateJwk, w.user.kid, OPEN_TYP) }), 'open_mandate', 403)
})

test('receipts are signed by the store, carry the AP2 claims, and fail on tampering', () => {
  const key = generateUserKey()
  const ref = sha256b64u('closed-mandate')
  const ok = createMandateReceipt({ issuer: 'https://shop.example/shop/vsemporium', key, reference: ref, now: NOW })
  const v = verifyJws(ok.jws, key.publicJwk, MANDATE_RECEIPT_TYP)
  assert.equal(v.ok, true)
  assert.deepEqual(v.payload, { iss: 'https://shop.example/shop/vsemporium', iat: Math.floor(NOW / 1000), result: 'success', reference: ref })
  const bad = createMandateReceipt({ issuer: 'x', key, reference: ref, error: 'unresolved_constraint', description: 'over the limit', now: NOW })
  assert.equal(decodeJws(bad.jws).payload.result, 'error')
  assert.equal(decodeJws(bad.jws).payload.error, 'unresolved_constraint')
  const pay = createPaymentReceipt({ issuer: 'x', key, reference: ref, paymentId: 'ord_1', txHash: '0xabc', now: NOW })
  assert.deepEqual(verifyJws(pay.jws, key.publicJwk, PAYMENT_RECEIPT_TYP).payload, { iss: 'x', iat: Math.floor(NOW / 1000), status: 'Success', reference: ref, payment_id: 'ord_1', network_confirmation_id: '0xabc' })
  assert.equal(decodeJws(createPaymentReceipt({ issuer: 'x', key, reference: ref, paymentId: 'ord_1', error: 'payment_failed', description: 'reverted', now: NOW }).jws).payload.status, 'Error')
  // wrong key, wrong type
  assert.equal(verifyJws(ok.jws, generateUserKey().publicJwk, MANDATE_RECEIPT_TYP).ok, false)
  assert.equal(verifyJws(ok.jws, key.publicJwk, PAYMENT_RECEIPT_TYP).ok, false)
})

test('failed checks map onto AP2 mandate-receipt error codes', () => {
  assert.equal(mandateErrorCode('open_mandate', 'open mandate signature rejected: bad_signature'), 'invalid_credential')
  assert.equal(mandateErrorCode('closed_mandate', 'closed mandate signature rejected: bad_signature'), 'invalid_credential')
  assert.equal(mandateErrorCode('amount_in_range', 'over'), 'unresolved_constraint')
  assert.equal(mandateErrorCode('budget_available', 'over'), 'unresolved_constraint')
  assert.equal(mandateErrorCode('payee_allowed', 'no'), 'unresolved_constraint')
  assert.equal(mandateErrorCode('mandate_active', 'revoked'), 'invalid_mandate')
  assert.equal(mandateErrorCode('closed_mandate', 'different order'), 'invalid_mandate')
})

test('amounts compare exactly and the order hash ignores key order', () => {
  assert.equal(toMicro('0.000001'), 1n)
  assert.equal(toMicro('89'), 89_000_000n)
  assert.equal(toMicro('1.1234567'), null)
  assert.equal(toMicro('-1'), null)
  assert.equal(fromMicro(89_500_000n), '89.5')
  assert.equal(fromMicro(300_000_000n), '300')
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}')
  assert.equal(orderHash({ sku: 'X', amount: '1', currency: 'OUSD', merchant: 'm', quantity: 1 }), orderHash({ merchant: 'm', quantity: 1, currency: 'OUSD', amount: '1', sku: 'X' }))
})
