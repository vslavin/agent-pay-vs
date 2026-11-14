import { orderHash, orderOf, sha256b64u, canonicalJson, verifyJws, decodeJws, toMicro, fromMicro, OPEN_TYP, CLOSED_TYP, OPEN_VCT, CLOSED_VCT, MANDATE_RECEIPT_TYP, PAYMENT_RECEIPT_TYP } from './mandate.mjs'
import { verifyRequest, thumbprint } from './tap.mjs'
import { verifyIdToken, decodeIdToken } from './oidc.mjs'
import { findPayment } from './payment.mjs'

// Evidence for one purchase: everything a third party needs to check who authorized what, without trusting the
// operator's database. Pure functions: the bundle goes in, a list of checked steps comes out.
//
// Two things bind a human to a mandate or a cart approval. The user signs in again with Keycloak, and the app puts a
// hash of the exact terms in that sign-in's `nonce`. Keycloak signs the resulting ID token, so the token shows that this
// account authenticated at that moment for those terms. The wallet service verifies it before it signs anything.

export const EVIDENCE_VERSION = 'agent-pay-evidence/1'
export const AUTH_FRESH_SECONDS = 120

export const normAmount = (text) => fromMicro(toMicro(text))
export const mandateTerms = ({ sub, agentId, merchants, maxPerPurchase, budget, hours }) =>
  ({ type: 'mandate', sub, agentId, merchants: [...new Set(merchants)].sort(), maxPerPurchase: normAmount(maxPerPurchase), budget: normAmount(budget), hours })
export const approvalTerms = ({ approvalId, orderHash: hash, mandateId }) => ({ type: 'approval', approvalId, orderHash: hash, mandateId })
export const termsHash = (terms) => sha256b64u(canonicalJson(terms))

// Rebuilds the mandate terms from a signed open mandate, so a verifier can recompute what the user approved.
export function termsFromOpenMandate(open) {
  const c = (t) => (open.constraints ?? []).find((x) => x.type === t) ?? {}
  return mandateTerms({
    sub: open.iss, agentId: open.sub, merchants: (c('payment.allowed_payees').allowed ?? []).map((p) => p.id),
    maxPerPurchase: fromMicro(BigInt(c('payment.amount_range').max)), budget: fromMicro(BigInt(c('payment.budget').max)),
    hours: Math.round((open.exp - open.iat) / 3600),
  })
}

const step = (name, status, detail) => ({ name, status, detail })   // status: pass | fail | warn | skip
const createdSec = (signatureInput) => Number(String(signatureInput ?? '').match(/created=(\d+)/)?.[1])

// Checks one proof (Keycloak ID token) against the exact terms. at = the moment the thing it authorizes was created (s).
function checkProof({ proof, terms, expectSub, at, jwks, issuer, audience }) {
  if (!proof) return step('proof', 'fail', 'no proof of sign-in was kept')
  if (proof.mode === 'dev-unproven') return step('proof', 'warn', 'created in development mode: the wallet service accepted it without a Keycloak sign-in')
  const t = decodeIdToken(proof.idToken)
  if (!t) return step('proof', 'fail', 'the kept ID token is malformed')
  // Verify as of the moment it was issued: tokens are short-lived and this check happens later.
  const v = verifyIdToken(proof.idToken, { jwks, issuer, audience, now: (t.claims.iat + 1) * 1000 })
  if (!v.ok) return step('proof', 'fail', `ID token did not verify: ${v.reason}`)
  if (v.claims.sub !== expectSub) return step('proof', 'fail', 'the ID token is for a different account')
  if (v.claims.nonce !== termsHash(terms)) return step('proof', 'fail', 'the sign-in was not bound to these exact terms (nonce mismatch)')
  const age = at - v.claims.auth_time
  if (!Number.isFinite(age) || age < -5 || age > AUTH_FRESH_SECONDS + 5) return step('proof', 'fail', `the sign-in was ${age}s before the signature, outside the ${AUTH_FRESH_SECONDS}s limit`)
  return step('proof', 'pass', `Keycloak (${issuer}) signed a sign-in for ${v.claims.sub}, ${age}s before, bound to these terms${v.claims.amr ? `; amr ${JSON.stringify(v.claims.amr)}` : ''}`)
}

// opts: { oidcJwks (override the bundle's, for independence), chainReceipt: { status, logs } }
export function verifyEvidence(bundle, opts = {}) {
  const steps = []
  const add = (s) => { steps.push(s); return s.status !== 'fail' }
  try {
    const { order, mandates, request, receipts, grant, approval, chain, keys } = bundle ?? {}
    if (bundle?.version !== EVIDENCE_VERSION || !order || !mandates?.open || !mandates?.closed || !receipts?.mandate || !keys?.user || !keys?.agent || !keys?.store) {
      return { ok: false, proven: false, steps: [step('structure', 'fail', 'not an Agent Pay evidence bundle, or parts are missing')] }
    }
    add(step('structure', 'pass', `order ${order.id}: ${order.item ?? order.sku} for ${order.amount} ${order.currency} at ${order.merchant}`))

    // Receipts: signed by the store, referencing the closed mandate.
    const mr = verifyJws(receipts.mandate, keys.store.jwk, MANDATE_RECEIPT_TYP)
    const closedHash = sha256b64u(mandates.closed)
    if (!mr.ok) add(step('mandate_receipt', 'fail', `store's mandate receipt: ${mr.reason}`))
    else if (mr.payload.result !== 'success') add(step('mandate_receipt', 'fail', `the store's receipt says ${mr.payload.result}`))
    else if (mr.payload.reference !== closedHash) add(step('mandate_receipt', 'fail', 'the receipt does not reference this closed mandate'))
    else add(step('mandate_receipt', 'pass', `store signed: accepted closed mandate ${closedHash.slice(0, 10)}…`))
    if (order.status === 'paid') {
      const pr = receipts.payment ? verifyJws(receipts.payment, keys.store.jwk, PAYMENT_RECEIPT_TYP) : { ok: false, reason: 'missing' }
      if (!pr.ok) add(step('payment_receipt', 'fail', `store's payment receipt: ${pr.reason}`))
      else if (pr.payload.status !== 'Success' || pr.payload.payment_id !== order.id || pr.payload.network_confirmation_id !== order.txHash || pr.payload.reference !== closedHash) {
        add(step('payment_receipt', 'fail', 'the payment receipt does not match this order, transaction and closed mandate'))
      } else add(step('payment_receipt', 'pass', `store signed: ${order.id} paid by transaction ${order.txHash.slice(0, 12)}…`))
    } else add(step('payment_receipt', 'skip', `order is ${order.status}: no payment receipt expected`))

    // Open mandate: signed by the user.
    const open = verifyJws(mandates.open, keys.user.jwk, OPEN_TYP)
    if (!open.ok) { add(step('open_mandate', 'fail', `signature: ${open.reason}`)); return finish(steps) }
    const om = open.payload
    const createdAt = Math.floor(Date.parse(order.createdAt) / 1000)
    if (om.vct !== OPEN_VCT || om.iss !== keys.user.sub || om.sub !== keys.agent.id || !(om.iat <= createdAt + 5 && createdAt < om.exp)) {
      add(step('open_mandate', 'fail', 'wrong type, wrong user or agent, or the order was made outside its validity period'))
    } else add(step('open_mandate', 'pass', `signed by user ${om.iss} for agent ${om.sub}, valid ${new Date(om.iat * 1000).toISOString()} to ${new Date(om.exp * 1000).toISOString()}`))

    // Closed mandate: signed by the agent whose key the open mandate names.
    const agentKid = om.cnf?.jwk ? thumbprint(om.cnf.jwk) : null
    const closed = verifyJws(mandates.closed, om.cnf?.jwk, CLOSED_TYP)
    const want = orderOf({ merchant: order.merchant, sku: order.sku, amount: order.amount, currency: order.currency })
    if (!closed.ok) add(step('closed_mandate', 'fail', `signature: ${closed.reason}`))
    else {
      const cm = closed.payload
      const problems = []
      if (cm.vct !== CLOSED_VCT) problems.push('wrong type')
      if (cm.open !== sha256b64u(mandates.open)) problems.push('refers to a different open mandate')
      if (cm.transaction_id !== orderHash(want)) problems.push('signed for a different order')
      if (cm.payee?.id !== order.merchant || cm.payment_amount?.amount !== Number(toMicro(order.amount)) || cm.payment_amount?.currency !== order.currency) problems.push('different payee or amount')
      if (agentKid !== keys.agent.kid) problems.push('the signing key is not the agent in this bundle')
      add(problems.length ? step('closed_mandate', 'fail', problems.join('; ')) : step('closed_mandate', 'pass', `signed by agent key ${agentKid.slice(0, 10)}… for exactly this order and payee`))
    }

    // Do the user's limits cover this order?
    const cons = (t) => (om.constraints ?? []).find((c) => c.type === t) ?? {}
    const payeeOk = (cons('payment.allowed_payees').allowed ?? []).some((p) => p.id === order.merchant)
    const amount = toMicro(order.amount)
    const within = amount !== null && amount <= BigInt(cons('payment.amount_range').max ?? -1) && amount >= BigInt(cons('payment.amount_range').min ?? 0)
    add(payeeOk && within ? step('limits', 'pass', `${order.merchant} is an allowed payee and ${order.amount} is within the per-purchase limit (the total budget cannot be checked from one order)`)
      : step('limits', 'fail', `${payeeOk ? '' : 'payee not allowed; '}${within ? '' : 'amount outside the per-purchase limit'}`))

    // The agent's signed HTTP request.
    if (!request?.headers) add(step('agent_request', 'fail', 'the signed request was not kept'))
    else {
      const created = createdSec(request.headers['signature-input'])
      const r = verifyRequest({ headers: request.headers, authority: request.authority, path: request.path, lookupKey: (id) => (id === keys.agent.kid ? keys.agent.jwk : null), seenNonces: new Map(), now: (created + 1) * 1000 })
      add(!r.ok ? step('agent_request', 'fail', `TAP-style signature: ${r.reason}`)
        : r.tag !== 'agent-payer-auth' ? step('agent_request', 'fail', `wrong tag ${r.tag}`)
        : step('agent_request', 'pass', `agent key ${r.keyid.slice(0, 10)}… signed ${request.authority}${request.path} at ${new Date(r.created * 1000).toISOString()}`))
    }

    // How the user's authority was created: a Keycloak sign-in bound to the mandate terms.
    const oidc = opts.oidcJwks ? { ...keys.oidc, jwks: opts.oidcJwks } : keys.oidc
    add({ ...checkProof({ proof: grant?.proof, terms: termsFromOpenMandate(om), expectSub: om.iss, at: om.iat, jwks: oidc?.jwks, issuer: oidc?.issuer, audience: oidc?.audience }), name: 'mandate_grant_proof' })

    // Per-purchase approval (human-present stores).
    if (!approval) add(step('approval_proof', 'skip', 'autonomous purchase: the mandate alone authorized it, no per-purchase approval was required'))
    else {
      const terms = approvalTerms({ approvalId: approval.id, orderHash: orderHash(want), mandateId: om.jti })
      const decided = Math.floor(Date.parse(approval.decidedAt) / 1000)
      add({ ...checkProof({ proof: approval.proof, terms, expectSub: om.iss, at: decided, jwks: oidc?.jwks, issuer: oidc?.issuer, audience: oidc?.audience }), name: 'approval_proof' })
    }

    // The transfer itself.
    if (opts.chainReceipt) {
      if (opts.chainReceipt.status !== 'success') add(step('chain', 'fail', 'the transaction did not succeed on the network'))
      else {
        const f = findPayment({ logs: opts.chainReceipt.logs, token: chain.token, payer: chain.payer, payee: chain.payee, amountMicro: toMicro(order.amount), memo: order.id })
        add(f.ok ? step('chain', 'pass', `the network shows ${order.amount} ${order.currency} from ${chain.payer.slice(0, 10)}… to ${chain.payee.slice(0, 10)}… with memo ${order.id}`) : step('chain', 'fail', f.reason))
      }
    } else add(step('chain', 'skip', `not checked here: look up ${order.txHash ?? 'the transaction'} on the network (run with --chain)`))
  } catch (e) {
    steps.push(step('error', 'fail', `could not check the bundle: ${e.message}`))
  }
  return finish(steps)
}

function finish(steps) {
  return { ok: steps.every((s) => s.status !== 'fail'), proven: steps.every((s) => s.status === 'pass' || s.status === 'skip'), steps }
}
