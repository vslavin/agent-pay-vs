import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto'
import { thumbprint, verifyRequest } from './tap.mjs'

// AP2-style payment mandates, signed as compact JWS (EdDSA) and bound to an agent's key.
//   open mandate   (vct mandate.payment.open.1) signed by the USER: what an agent may do on its own, as an array of
//                  typed constraints (payment.allowed_payees, payment.amount_range, payment.budget) plus expiry.
//                  Its `cnf` claim carries the agent's public key, so it works for that agent only.
//   closed mandate (vct mandate.payment.1) signed by the AGENT: one specific purchase, bound to the open mandate and
//                  to the exact order (transaction_id).
//   receipts       signed by the STORE as verifier: a Mandate Receipt for each checkout decision and a Payment Receipt
//                  once the on-chain payment is confirmed.
// Differences from AP2 v0.2, on purpose: plain JWS instead of SD-JWT (no selective disclosure or key-binding JWT);
// no checkout mandate (the order hash stands in for a merchant-signed checkout JWT); amounts are integer minor units
// of OUSD (6 decimals, not an ISO 4217 currency); payee carries an `address` because the payment is an on-chain
// transfer. The checkout decision combines all this with the agent's TAP-style request signature. Pure functions:
// no network, no storage; callers inject lookups.

export const OPEN_TYP = 'ap2-mandate-open+jwt'
export const CLOSED_TYP = 'ap2-mandate-closed+jwt'
export const MANDATE_RECEIPT_TYP = 'ap2-mandate-receipt+jwt'
export const PAYMENT_RECEIPT_TYP = 'ap2-payment-receipt+jwt'
export const OPEN_VCT = 'mandate.payment.open.1'
export const CLOSED_VCT = 'mandate.payment.1'
export const CLOSED_WINDOW_SECONDS = 8 * 60

const KNOWN_CONSTRAINTS = new Set(['payment.allowed_payees', 'payment.amount_range', 'payment.budget'])
const asInt = (v) => (Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null)
const b64u = (buf) => Buffer.from(buf).toString('base64url')

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys)
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]))
  return v
}
export const canonicalJson = (v) => JSON.stringify(sortKeys(v))
export const sha256b64u = (s) => createHash('sha256').update(s).digest('base64url')

// Amounts are decimal strings with up to 6 decimals, compared exactly as integers of millionths.
export function toMicro(text) {
  if (typeof text !== 'string' || !/^\d+(\.\d{1,6})?$/.test(text)) return null
  const [whole, frac = ''] = text.split('.')
  return BigInt(whole) * 1_000_000n + BigInt(frac.padEnd(6, '0'))
}
export const fromMicro = (n) => {
  const s = n.toString().padStart(7, '0')
  return `${s.slice(0, -6)}.${s.slice(-6)}`.replace(/\.?0+$/, '') || '0'
}

// The order the merchant and the agent must both be able to compute from the catalog.
export const orderOf = ({ merchant, sku, quantity = 1, amount, currency = 'OUSD' }) => ({ amount, currency, merchant, quantity, sku })
export const orderHash = (order) => sha256b64u(canonicalJson(order))

export function generateUserKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicJwk = publicKey.export({ format: 'jwk' })
  return { kid: thumbprint(publicJwk), publicJwk, privateJwk: privateKey.export({ format: 'jwk' }) }
}

export function signJws(payload, privateJwk, kid, typ) {
  const head = b64u(JSON.stringify({ alg: 'EdDSA', typ, kid }))
  const body = b64u(JSON.stringify(payload))
  const sig = sign(null, Buffer.from(`${head}.${body}`), createPrivateKey({ key: privateJwk, format: 'jwk' }))
  return `${head}.${body}.${b64u(sig)}`
}

export function decodeJws(token) {
  if (typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return null
  try {
    return { header: JSON.parse(Buffer.from(parts[0], 'base64url')), payload: JSON.parse(Buffer.from(parts[1], 'base64url')), signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') }
  } catch { return null }
}

export function verifyJws(token, publicJwk, typ) {
  const d = decodeJws(token)
  if (!d) return { ok: false, reason: 'malformed' }
  if (d.header.alg !== 'EdDSA' || d.header.typ !== typ) return { ok: false, reason: 'wrong_type' }
  let good = false
  try { good = verify(null, Buffer.from(d.signingInput), createPublicKey({ key: publicJwk, format: 'jwk' }), d.signature) } catch { good = false }
  return good ? { ok: true, header: d.header, payload: d.payload } : { ok: false, reason: 'bad_signature' }
}

// constraints: { merchants: [usernames], merchantNames?: { username: name }, maxPerPurchase: '150', budget: '300', currency: 'OUSD' }
// Amounts arrive as decimal strings and are written into the mandate as integer minor units (millionths of OUSD).
export function createOpenMandate({ user, userSub, agent, constraints, ttlSeconds, now = Date.now(), id = `mnd_${randomBytes(6).toString('hex')}` }) {
  const iat = Math.floor(now / 1000)
  const currency = constraints.currency ?? 'OUSD'
  const payload = {
    vct: OPEN_VCT, jti: id, iss: userSub, sub: agent.id, iat, exp: iat + ttlSeconds,
    cnf: { jwk: agent.publicJwk },
    constraints: [
      { type: 'payment.allowed_payees', allowed: constraints.merchants.map((m) => ({ id: m, name: constraints.merchantNames?.[m] ?? m })) },
      { type: 'payment.amount_range', currency, min: 0, max: Number(toMicro(constraints.maxPerPurchase)) },
      { type: 'payment.budget', currency, max: Number(toMicro(constraints.budget)) },
    ],
  }
  return { id, payload, jws: signJws(payload, user.privateJwk, user.kid, OPEN_TYP) }
}

export function createClosedMandate({ agentKey, openJws, order, payee, now = Date.now(), ttlSeconds = 300, nonce = randomBytes(12).toString('base64url') }) {
  const iat = Math.floor(now / 1000)
  const payload = {
    vct: CLOSED_VCT, jti: `cls_${randomBytes(6).toString('hex')}`, iat, exp: iat + ttlSeconds, nonce,
    open: sha256b64u(openJws), transaction_id: orderHash(order),
    payee: { id: order.merchant, address: payee },
    payment_amount: { amount: Number(toMicro(order.amount)), currency: order.currency },
  }
  return { payload, jws: signJws(payload, agentKey.privateJwk, agentKey.keyid, CLOSED_TYP) }
}

// ── Receipts: signed by the store (the verifier). ───────────────────────────────────────────────────────────
// Mandate Receipt: { iss, iat, result: 'success'|'error', reference, error?, error_description? }
//   reference = hash of the mandate the store received (the closed one, or the open one if no closed was sent).
// Payment Receipt: { iss, iat, status: 'Success'|'Error', reference, payment_id, network_confirmation_id? , error?, error_description? }
//   reference = hash of the closed mandate; payment_id = the order id; network_confirmation_id = the transaction hash.
export function createMandateReceipt({ issuer, key, reference, error, description, now = Date.now() }) {
  const payload = { iss: issuer, iat: Math.floor(now / 1000), result: error ? 'error' : 'success', reference, ...(error ? { error, error_description: description } : {}) }
  return { payload, jws: signJws(payload, key.privateJwk, key.kid, MANDATE_RECEIPT_TYP) }
}
export function createPaymentReceipt({ issuer, key, reference, paymentId, txHash, error, description, now = Date.now() }) {
  const payload = { iss: issuer, iat: Math.floor(now / 1000), status: error ? 'Error' : 'Success', reference, payment_id: paymentId,
    ...(error ? { error, error_description: description } : { network_confirmation_id: txHash }) }
  return { payload, jws: signJws(payload, key.privateJwk, key.kid, PAYMENT_RECEIPT_TYP) }
}
// Maps one of our failed checks to the AP2 mandate-receipt error vocabulary.
export function mandateErrorCode(check, detail = '') {
  if (/signature rejected|not signed by a known user/.test(detail)) return 'invalid_credential'
  if (['merchant_allowed', 'payee_allowed', 'amount_in_range', 'budget_available', 'constraints_understood', 'purchase_mode'].includes(check)) return 'unresolved_constraint'
  return 'invalid_mandate'
}

// lookups: {
//   agentPublicJwk(keyid) -> jwk|null,  userPublicJwk(sub) -> jwk|null,
//   mandateRecord(jti) -> { status } | null,  spentMicro(jti) -> BigInt,
//   seenNonces: Map (TAP request nonces),  usedClosed: Set (closed mandate nonces),
//   approvalFor(orderHash, mandateId) -> { id, status: pending|approved|reserved|rejected, orderId? } | null  (human-present stores only)
// }
// Returns { ok, status, code, checks, context }. status is the HTTP-style class: 401 identity, 403 mandate.
export function evaluateCheckout({ now = Date.now(), request, order, mandates, merchant, policy = { mode: 'autonomous' }, lookups }) {
  const checks = []
  const nowSec = Math.floor(now / 1000)
  const fail = (name, status, detail) => {
    checks.push({ name, ok: false, detail })
    return { ok: false, status, code: name, checks, context }
  }
  const pass = (name, detail) => checks.push({ name, ok: true, detail })
  const context = {}

  // 1. Who is calling: TAP-style signed request.
  const sig = verifyRequest({ headers: request.headers, authority: request.authority, path: request.path, lookupKey: lookups.agentPublicJwk, seenNonces: lookups.seenNonces, now })
  if (!sig.ok) return fail('agent_signature', 401, `request signature rejected: ${sig.reason}`)
  if (sig.tag !== 'agent-payer-auth') return fail('agent_signature', 401, `checkout needs tag agent-payer-auth, got ${sig.tag}`)
  context.keyid = sig.keyid
  pass('agent_signature', 'signed request verified against the key registry')

  // 2-3. The user's open mandate.
  const openJws = mandates?.open
  if (!openJws) return fail('open_mandate', 403, 'no open mandate presented: the agent has no authority to buy')
  const draft = decodeJws(openJws)
  if (!draft || !draft.payload?.iss) return fail('open_mandate', 403, 'open mandate is malformed')
  const userJwk = lookups.userPublicJwk(draft.payload.iss)
  if (!userJwk) return fail('open_mandate', 403, 'open mandate was not signed by a known user')
  const open = verifyJws(openJws, userJwk, OPEN_TYP)
  if (!open.ok) return fail('open_mandate', 403, `open mandate signature rejected: ${open.reason}`)
  const m = open.payload
  context.mandateId = m.jti
  context.referenceHash = sha256b64u(openJws)
  if (m.vct !== OPEN_VCT) return fail('open_mandate', 403, `open mandate has the wrong type ${String(m.vct).slice(0, 40)}`)
  pass('open_mandate', `signed by the user, id ${m.jti}`)

  // 4. Bound to this agent's key.
  const bound = m.cnf?.jwk ? thumbprint(m.cnf.jwk) : null
  if (bound !== sig.keyid) return fail('mandate_bound_to_agent', 403, 'the mandate was issued to a different agent key')
  pass('mandate_bound_to_agent', 'mandate key matches the signing agent')

  // 5. Still valid: known to us, not revoked, not expired.
  const record = lookups.mandateRecord(m.jti)
  if (!record) return fail('mandate_active', 403, 'unknown mandate')
  if (record.status === 'revoked') return fail('mandate_active', 403, 'mandate was revoked by the user')
  if (!Number.isInteger(m.exp) || nowSec >= m.exp) return fail('mandate_active', 403, 'mandate has expired')
  pass('mandate_active', 'not expired, not revoked')

  // 6-8. Constraints: an array of typed objects. A constraint type we do not know must fail the evaluation.
  const list = Array.isArray(m.constraints) ? m.constraints : []
  const unknown = list.find((c) => !KNOWN_CONSTRAINTS.has(c?.type))
  if (unknown) return fail('constraints_understood', 403, `the mandate has a constraint this store cannot evaluate: ${String(unknown?.type).slice(0, 60)}`)
  const byType = (t) => list.find((c) => c.type === t)
  const payees = byType('payment.allowed_payees')
  if (!Array.isArray(payees?.allowed) || !payees.allowed.some((p) => p?.id === merchant.username)) {
    return fail('payee_allowed', 403, `this merchant is not on the mandate's allowed payees`)
  }
  pass('payee_allowed', 'merchant is an allowed payee')
  const amount = toMicro(order.amount)
  const range = byType('payment.amount_range') ?? {}
  const max = asInt(range.max), min = asInt(range.min ?? 0)
  if (amount === null || max === null || min === null || range.currency !== order.currency) return fail('amount_in_range', 403, 'amount or currency does not match the mandate')
  if (amount < min || amount > max) return fail('amount_in_range', 403, `${order.amount} ${order.currency} is outside the per-purchase limit of ${fromMicro(max)}`)
  pass('amount_in_range', `${order.amount} is within the per-purchase limit of ${fromMicro(max)}`)
  const bud = byType('payment.budget') ?? {}
  const budget = asInt(bud.max)
  const spent = lookups.spentMicro(m.jti)
  if (budget === null || bud.currency !== order.currency) return fail('budget_available', 403, 'mandate has no valid budget')
  if (spent + amount > budget) return fail('budget_available', 403, `would exceed the budget: ${fromMicro(spent)} of ${fromMicro(budget)} already used`)
  pass('budget_available', `${fromMicro(budget - spent - amount)} would remain of ${fromMicro(budget)}`)

  // 9-10. The agent's closed mandate for exactly this purchase.
  const closedJws = mandates?.closed
  if (!closedJws) return fail('closed_mandate', 403, 'no closed mandate for this purchase')
  context.referenceHash = sha256b64u(closedJws)
  const closed = verifyJws(closedJws, m.cnf.jwk, CLOSED_TYP)
  if (!closed.ok) return fail('closed_mandate', 403, `closed mandate signature rejected: ${closed.reason}`)
  const cm = closed.payload
  if (cm.vct !== CLOSED_VCT) return fail('closed_mandate', 403, `closed mandate has the wrong type ${String(cm.vct).slice(0, 40)}`)
  if (cm.open !== sha256b64u(openJws)) return fail('closed_mandate', 403, 'closed mandate refers to a different open mandate')
  if (cm.transaction_id !== orderHash(order)) return fail('closed_mandate', 403, 'closed mandate was signed for a different order')
  const pay = cm.payment_amount ?? {}
  const to = cm.payee ?? {}
  if (to.id !== merchant.username || String(to.address).toLowerCase() !== String(merchant.address).toLowerCase() || asInt(pay.amount) !== amount || pay.currency !== order.currency) {
    return fail('closed_mandate', 403, 'closed mandate pays a different payee or amount')
  }
  if (!Number.isInteger(cm.iat) || !Number.isInteger(cm.exp) || cm.iat > nowSec + 60 || nowSec >= cm.exp || cm.exp - cm.iat > CLOSED_WINDOW_SECONDS) {
    return fail('closed_mandate', 403, 'closed mandate is outside its validity window')
  }
  if (lookups.usedClosed.has(cm.jti) || lookups.usedClosed.has(`n:${cm.nonce}`)) return fail('closed_mandate', 403, 'closed mandate was already used')
  pass('closed_mandate', 'signed by the agent for exactly this order and payee')

  // 11. How much human involvement this merchant demands.
  context.orderHash = orderHash(order)
  if (policy.mode === 'autonomous') {
    pass('purchase_mode', 'this store accepts autonomous purchases within a mandate')
  } else if (policy.mode === 'human_present') {
    // The user must have approved this exact cart (same order hash, same mandate) with a fresh passkey sign-in.
    const ap = lookups.approvalFor?.(context.orderHash, m.jti) ?? null
    if (ap?.status === 'approved') {
      context.approvalId = ap.id
      pass('purchase_mode', `the user approved this exact purchase (${ap.id}) with a fresh passkey sign-in`)
    } else if (ap?.status === 'rejected') {
      return fail('purchase_mode', 403, `the user declined this purchase (${ap.id})`)
    } else if (ap?.status === 'reserved') {
      context.approvalId = ap.id
      return fail('purchase_mode', 403, `this approved purchase already has an open quote (${ap.orderId}): pay it, or wait for it to expire and ask again`)
    } else if (ap?.status === 'pending') {
      context.approvalId = ap.id
      return fail('purchase_mode', 403, `this store needs the user to approve this exact purchase: approval ${ap.id} is waiting for them`)
    } else {
      context.needsApproval = true
      return fail('purchase_mode', 403, 'this store needs the user to approve this exact purchase: an approval request has been opened')
    }
  } else {
    return fail('purchase_mode', 403, `unknown purchase mode ${policy.mode}: refused`)
  }

  return { ok: true, status: 200, code: 'authorized', checks, context: { ...context, amountMicro: amount, closedId: cm.jti, closedNonce: cm.nonce, closedHash: context.referenceHash, agentId: m.sub } }
}
