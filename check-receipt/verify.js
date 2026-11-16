// Check Receipt: the verifier. No dependencies, no network, no server: it uses the browser's own WebCrypto
// (Ed25519 and RSA-SHA256), so the same file runs in a page and under Node 20+. Everything here is a plain function
// that takes the pieces of evidence and returns a list of checked steps. Nothing is trusted because of where it came
// from; every claim is rebuilt from the signed material.
//
// This is a second, independent implementation of the checks in agent-wallet-demo/wallet-service/evidence.mjs. A test
// (test/parity.test.mjs) feeds both the same bundles, honest and tampered, and requires the same verdict.

const subtle = globalThis.crypto.subtle
const enc = new TextEncoder()
const dec = new TextDecoder()

export const EVIDENCE_VERSION = 'agent-pay-evidence/1'
export const AUTH_FRESH_SECONDS = 120
export const OPEN_TYP = 'ap2-mandate-open+jwt'
export const CLOSED_TYP = 'ap2-mandate-closed+jwt'
export const MANDATE_RECEIPT_TYP = 'ap2-mandate-receipt+jwt'
export const PAYMENT_RECEIPT_TYP = 'ap2-payment-receipt+jwt'
export const OPEN_VCT = 'mandate.payment.open.1'
export const CLOSED_VCT = 'mandate.payment.1'
export const MEMO_TOPIC = '0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0'
const TAP_TAGS = ['agent-browser-auth', 'agent-payer-auth']
const TAP_WINDOW_SECONDS = 8 * 60
const TAP_SKEW_SECONDS = 60

// ── encoding ────────────────────────────────────────────────────────────────────────────────────────────────
export const b64uToBytes = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}
export const bytesToB64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')

export const sha256b64u = async (text) => bytesToB64u(await subtle.digest('SHA-256', enc.encode(text)))

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys)
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]))
  return v
}
export const canonicalJson = (v) => JSON.stringify(sortKeys(v))

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
export const normAmount = (text) => fromMicro(toMicro(text))

// The order both the agent and the store must be able to compute from the catalog.
export const orderOf = ({ merchant, sku, quantity = 1, amount, currency = 'OUSD' }) => ({ amount, currency, merchant, quantity, sku })
export const orderHash = async (order) => sha256b64u(canonicalJson(order))

// ── keys and signatures ─────────────────────────────────────────────────────────────────────────────────────
const ed25519Key = (jwk) => subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify'])
const rsaKey = (jwk) => subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])

// The key's identity: a SHA-256 of its public parts (RFC 7638 style, as the agent registry uses).
export const thumbprint = (jwk) => sha256b64u(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))

export function decodeJws(token) {
  if (typeof token !== 'string') return null
  const parts = token.trim().split('.')
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return null
  try {
    return { header: JSON.parse(dec.decode(b64uToBytes(parts[0]))), payload: JSON.parse(dec.decode(b64uToBytes(parts[1]))), signingInput: `${parts[0]}.${parts[1]}`, signature: b64uToBytes(parts[2]) }
  } catch { return null }
}

export async function verifyJws(token, publicJwk, typ) {
  const d = decodeJws(token)
  if (!d) return { ok: false, reason: 'malformed' }
  if (d.header.alg !== 'EdDSA' || d.header.typ !== typ) return { ok: false, reason: 'wrong_type' }
  let good = false
  try { good = await subtle.verify('Ed25519', await ed25519Key(publicJwk), d.signature, enc.encode(d.signingInput)) } catch { good = false }
  return good ? { ok: true, header: d.header, payload: d.payload } : { ok: false, reason: 'bad_signature' }
}

// An OpenID Connect ID token (RS256), the kind Keycloak signs. Only RS256 is accepted.
export function decodeIdToken(token) {
  if (typeof token !== 'string' || token.length > 20_000) return null
  const parts = token.trim().split('.')
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return null
  try { return { header: JSON.parse(dec.decode(b64uToBytes(parts[0]))), claims: JSON.parse(dec.decode(b64uToBytes(parts[1]))), signingInput: `${parts[0]}.${parts[1]}`, signature: b64uToBytes(parts[2]) } } catch { return null }
}

export async function verifyIdToken(token, { jwks, issuer, audience, now = Date.now() }) {
  const t = decodeIdToken(token)
  if (!t) return { ok: false, reason: 'malformed token' }
  if (t.header.alg !== 'RS256') return { ok: false, reason: `unsupported algorithm ${String(t.header.alg).slice(0, 12)}` }
  const jwk = (jwks?.keys ?? []).find((k) => k.kid === t.header.kid && k.kty === 'RSA' && (!k.use || k.use === 'sig'))
  if (!jwk) return { ok: false, reason: 'unknown signing key' }
  let good = false
  try { good = await subtle.verify('RSASSA-PKCS1-v1_5', await rsaKey(jwk), t.signature, enc.encode(t.signingInput)) } catch { good = false }
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

// ── the agent's signed HTTP request (RFC 9421, as in Visa's Trusted Agent Protocol) ─────────────────────────
function parseParams(text) {
  const out = {}
  for (const m of text.matchAll(/;\s*([a-z0-9_-]+)=(?:"([^"]*)"|([^;\s]+))/gi)) out[m[1].toLowerCase()] = m[2] ?? m[3]
  return out
}

// headers: { 'signature-input', 'signature' } (lower-case names). lookupKey(keyid) returns a public JWK or null.
export async function verifyRequest({ headers, authority, path, lookupKey, now = Date.now() }) {
  const input = headers?.['signature-input']
  const sigHeader = headers?.signature
  if (!input || !sigHeader) return { ok: false, reason: 'missing_signature' }
  const head = input.match(/^([A-Za-z][\w-]*)=\(([^)]*)\)(.*)$/s)
  const sig = sigHeader.match(/^([A-Za-z][\w-]*)=:([A-Za-z0-9+/]+={0,2}):$/)
  if (!head || !sig || head[1] !== sig[1]) return { ok: false, reason: 'malformed_signature' }
  const covered = [...head[2].matchAll(/"([^"]+)"/g)].map((m) => m[1])
  if (!covered.includes('@authority') || !covered.includes('@path')) return { ok: false, reason: 'missing_components' }
  const p = parseParams(head[3])
  for (const name of ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag']) if (p[name] == null) return { ok: false, reason: `missing_param_${name}` }
  if (!TAP_TAGS.includes(p.tag)) return { ok: false, reason: 'bad_tag' }
  if (p.alg.toLowerCase() !== 'ed25519') return { ok: false, reason: 'bad_alg' }
  const nowSec = Math.floor(now / 1000)
  const created = Number(p.created), expires = Number(p.expires)
  if (!Number.isInteger(created) || !Number.isInteger(expires)) return { ok: false, reason: 'malformed_signature' }
  if (created > nowSec + TAP_SKEW_SECONDS) return { ok: false, reason: 'created_in_future' }
  if (nowSec - created > TAP_WINDOW_SECONDS || expires <= nowSec) return { ok: false, reason: 'expired' }
  if (expires - created > TAP_WINDOW_SECONDS) return { ok: false, reason: 'window_too_long' }
  const jwk = lookupKey(p.keyid)
  if (!jwk) return { ok: false, reason: 'unknown_key' }
  const base = `"@authority": ${authority}\n"@path": ${path}\n"@signature-params": ${head[0].slice(head[1].length + 1)}`
  let good = false
  try { good = await subtle.verify('Ed25519', await ed25519Key(jwk), b64ToBytes(sig[2]), enc.encode(base)) } catch { good = false }
  if (!good) return { ok: false, reason: 'bad_signature' }
  return { ok: true, keyid: p.keyid, tag: p.tag, created, expires }
}

// ── the transfer on the network ─────────────────────────────────────────────────────────────────────────────
const addrOf = (topic) => `0x${String(topic).slice(-40)}`.toLowerCase()
// bytes32, right-padded with zeros: the order id as Tempo's transferWithMemo records it.
export function memoTopic(text) {
  const bytes = enc.encode(String(text))
  if (bytes.length === 0 || bytes.length > 32) throw new Error('memo must be 1 to 32 bytes')
  return `0x${hex(bytes).padEnd(64, '0')}`
}
// All four facts must hold in the same log: who paid, who was paid, how much, and for which order.
export function findPayment({ logs, token, payer, payee, amountMicro, memo }) {
  const want = memoTopic(memo)
  const same = (logs ?? []).filter((l) => String(l.address).toLowerCase() === String(token).toLowerCase() && l.topics?.[0] === MEMO_TOPIC && String(l.topics?.[3]).toLowerCase() === want)
  if (!same.length) return { ok: false, reason: `no OUSD transfer carries the memo ${memo}` }
  for (const log of same) {
    if (addrOf(log.topics[1]) !== String(payer).toLowerCase()) continue
    if (addrOf(log.topics[2]) !== String(payee).toLowerCase()) continue
    if (BigInt(log.data) !== BigInt(amountMicro)) continue
    return { ok: true, log }
  }
  const l = same[0]
  if (addrOf(l.topics[1]) !== String(payer).toLowerCase()) return { ok: false, reason: 'the transfer was not made by the mandate holder’s wallet' }
  if (addrOf(l.topics[2]) !== String(payee).toLowerCase()) return { ok: false, reason: 'the transfer went to a different payee' }
  return { ok: false, reason: 'the transfer amount does not match the order' }
}

// ── what the user's sign-in was bound to ────────────────────────────────────────────────────────────────────
// The app puts a hash of the exact terms in the `nonce` of a fresh Keycloak sign-in. Keycloak signs the resulting ID
// token, so the token shows that this account authenticated at that moment for those terms and no others.
export const mandateTerms = ({ sub, agentId, merchants, maxPerPurchase, budget, hours }) =>
  ({ type: 'mandate', sub, agentId, merchants: [...new Set(merchants)].sort(), maxPerPurchase: normAmount(maxPerPurchase), budget: normAmount(budget), hours })
export const approvalTerms = ({ approvalId, orderHash: hash, mandateId }) => ({ type: 'approval', approvalId, orderHash: hash, mandateId })
export const termsHash = (terms) => sha256b64u(canonicalJson(terms))

// Rebuilds the mandate terms from a signed open mandate, so a verifier recomputes what the user approved.
export function termsFromOpenMandate(open) {
  const c = (t) => (open.constraints ?? []).find((x) => x.type === t) ?? {}
  return mandateTerms({
    sub: open.iss, agentId: open.sub, merchants: (c('payment.allowed_payees').allowed ?? []).map((p) => p.id),
    maxPerPurchase: fromMicro(BigInt(c('payment.amount_range').max)), budget: fromMicro(BigInt(c('payment.budget').max)),
    hours: Math.round((open.exp - open.iat) / 3600),
  })
}

// ── the steps ───────────────────────────────────────────────────────────────────────────────────────────────
// status: pass | fail | warn | skip. (The page adds 'todo' for pieces that have not been supplied yet.)
const step = (name, status, detail) => ({ name, status, detail })
const createdSec = (signatureInput) => Number(String(signatureInput ?? '').match(/created=(\d+)/)?.[1])
const iso = (sec) => new Date(sec * 1000).toISOString()

export async function checkMandateReceipt({ receipt, storeJwk, closedJws }) {
  const mr = await verifyJws(receipt, storeJwk, MANDATE_RECEIPT_TYP)
  if (!mr.ok) return step('mandate_receipt', 'fail', `store's mandate receipt: ${mr.reason}`)
  if (mr.payload.result !== 'success') return step('mandate_receipt', 'fail', `the store's receipt says ${mr.payload.result}`)
  if (!closedJws) return step('mandate_receipt', 'warn', 'the store’s signature is valid, but the closed mandate was not supplied, so the receipt’s reference could not be compared')
  const closedHash = await sha256b64u(closedJws)
  if (mr.payload.reference !== closedHash) return step('mandate_receipt', 'fail', 'the receipt does not reference this closed mandate')
  return step('mandate_receipt', 'pass', `store signed: accepted closed mandate ${closedHash.slice(0, 10)}…`)
}

export async function checkPaymentReceipt({ receipt, storeJwk, closedJws, order }) {
  if (order?.status && order.status !== 'paid') return step('payment_receipt', 'skip', `order is ${order.status}: no payment receipt expected`)
  if (!receipt) return order?.status === 'paid' ? step('payment_receipt', 'fail', "store's payment receipt: missing") : step('payment_receipt', 'skip', 'no payment receipt supplied')
  const pr = await verifyJws(receipt, storeJwk, PAYMENT_RECEIPT_TYP)
  if (!pr.ok) return step('payment_receipt', 'fail', `store's payment receipt: ${pr.reason}`)
  const closedHash = closedJws ? await sha256b64u(closedJws) : null
  const p = pr.payload
  if (!order?.id || !order?.txHash) {
    if (p.status !== 'Success') return step('payment_receipt', 'fail', `the payment receipt says ${p.status}`)
    if (closedHash && p.reference !== closedHash) return step('payment_receipt', 'fail', 'the payment receipt does not match this closed mandate')
    return step('payment_receipt', 'warn', `store signed: ${p.payment_id} paid by transaction ${String(p.network_confirmation_id).slice(0, 12)}… (the order details were not supplied, so they were not compared)`)
  }
  if (p.status !== 'Success' || p.payment_id !== order.id || p.network_confirmation_id !== order.txHash || (closedHash && p.reference !== closedHash)) {
    return step('payment_receipt', 'fail', 'the payment receipt does not match this order, transaction and closed mandate')
  }
  return step('payment_receipt', 'pass', `store signed: ${order.id} paid by transaction ${order.txHash.slice(0, 12)}…`)
}

// userSub, agentId and order are optional: when given, they are compared too.
export async function checkOpenMandate({ openJws, userJwk, userSub, agentId, order }) {
  const open = await verifyJws(openJws, userJwk, OPEN_TYP)
  if (!open.ok) return step('open_mandate', 'fail', `signature: ${open.reason}`)
  const om = open.payload
  const createdAt = order?.createdAt ? Math.floor(Date.parse(order.createdAt) / 1000) : null
  const problems = om.vct !== OPEN_VCT
    || (userSub && om.iss !== userSub)
    || (agentId && om.sub !== agentId)
    || (createdAt !== null && !(om.iat <= createdAt + 5 && createdAt < om.exp))
  if (problems) return step('open_mandate', 'fail', 'wrong type, wrong user or agent, or the order was made outside its validity period')
  return step('open_mandate', 'pass', `signed by user ${om.iss} for agent ${om.sub}, valid ${iso(om.iat)} to ${iso(om.exp)}`)
}

// The closed mandate is signed by the agent key the open mandate names, so no key is supplied: it comes from the open one.
export async function checkClosedMandate({ closedJws, openJws, order, agentKid }) {
  let open = decodeJws(openJws)
  if (!open) return step('closed_mandate', 'fail', 'signature: the open mandate that names the agent’s key is missing or malformed')
  const om = open.payload
  const agentJwk = om.cnf?.jwk
  const kid = agentJwk ? await thumbprint(agentJwk) : null
  const closed = await verifyJws(closedJws, agentJwk, CLOSED_TYP)
  if (!closed.ok) return step('closed_mandate', 'fail', `signature: ${closed.reason}`)
  const cm = closed.payload
  const problems = []
  if (cm.vct !== CLOSED_VCT) problems.push('wrong type')
  if (cm.open !== await sha256b64u(openJws)) problems.push('refers to a different open mandate')
  if (order?.merchant) {
    const want = orderOf({ merchant: order.merchant, sku: order.sku, amount: order.amount, currency: order.currency })
    if (cm.transaction_id !== await orderHash(want)) problems.push('signed for a different order')
    if (cm.payee?.id !== order.merchant || cm.payment_amount?.amount !== Number(toMicro(order.amount)) || cm.payment_amount?.currency !== order.currency) problems.push('different payee or amount')
  }
  if (agentKid && kid !== agentKid) problems.push('the signing key is not the agent in this bundle')
  if (problems.length) return step('closed_mandate', 'fail', problems.join('; '))
  if (!order?.merchant) return step('closed_mandate', 'warn', `signed by agent key ${kid.slice(0, 10)}… and tied to the open mandate; the order details were not supplied, so payee, amount and order were not compared`)
  return step('closed_mandate', 'pass', `signed by agent key ${kid.slice(0, 10)}… for exactly this order and payee`)
}

// Do the user's limits cover this order? The total budget cannot be checked from a single order.
export function checkLimits({ openPayload: om, order }) {
  const cons = (t) => (om.constraints ?? []).find((c) => c.type === t) ?? {}
  const payeeOk = (cons('payment.allowed_payees').allowed ?? []).some((p) => p.id === order.merchant)
  const amount = toMicro(order.amount)
  const within = amount !== null && amount <= BigInt(cons('payment.amount_range').max ?? -1) && amount >= BigInt(cons('payment.amount_range').min ?? 0)
  return payeeOk && within
    ? step('limits', 'pass', `${order.merchant} is an allowed payee and ${order.amount} is within the per-purchase limit (the total budget cannot be checked from one order)`)
    : step('limits', 'fail', `${payeeOk ? '' : 'payee not allowed; '}${within ? '' : 'amount outside the per-purchase limit'}`)
}

export async function checkAgentRequest({ request, lookupKey }) {
  if (!request?.headers) return step('agent_request', 'fail', 'the signed request was not kept')
  const created = createdSec(request.headers['signature-input'])
  const r = await verifyRequest({ headers: request.headers, authority: request.authority, path: request.path, lookupKey, now: (created + 1) * 1000 })
  if (!r.ok) return step('agent_request', 'fail', `TAP-style signature: ${r.reason}`)
  if (r.tag !== 'agent-payer-auth') return step('agent_request', 'fail', `wrong tag ${r.tag}`)
  return step('agent_request', 'pass', `agent key ${r.keyid.slice(0, 10)}… signed ${request.authority}${request.path} at ${iso(r.created)}`)
}

// Checks one proof (a Keycloak ID token) against the exact terms. at = when the thing it authorizes was created (s).
export async function checkProof({ name, proof, terms, expectSub, at, jwks, issuer, audience }) {
  const done = (s) => ({ ...s, name })
  if (!proof) return done(step('proof', 'fail', 'no proof of sign-in was kept'))
  if (proof.mode === 'dev-unproven') return done(step('proof', 'warn', 'created in development mode: the wallet service accepted it without a Keycloak sign-in'))
  const t = decodeIdToken(proof.idToken)
  if (!t) return done(step('proof', 'fail', 'the kept ID token is malformed'))
  // Verify as of the moment it was issued: tokens are short-lived and this check happens later.
  const v = await verifyIdToken(proof.idToken, { jwks, issuer, audience, now: (t.claims.iat + 1) * 1000 })
  if (!v.ok) return done(step('proof', 'fail', `ID token did not verify: ${v.reason}`))
  if (v.claims.sub !== expectSub) return done(step('proof', 'fail', 'the ID token is for a different account'))
  if (v.claims.nonce !== await termsHash(terms)) return done(step('proof', 'fail', 'the sign-in was not bound to these exact terms (nonce mismatch)'))
  const age = at - v.claims.auth_time
  if (!Number.isFinite(age) || age < -5 || age > AUTH_FRESH_SECONDS + 5) return done(step('proof', 'fail', `the sign-in was ${age}s before the signature, outside the ${AUTH_FRESH_SECONDS}s limit`))
  return done(step('proof', 'pass', `Keycloak (${issuer}) signed a sign-in for ${v.claims.sub}, ${age}s before, bound to these terms${v.claims.amr ? `; amr ${JSON.stringify(v.claims.amr)}` : ''}`))
}

// chainReceipt: { status: 'success' | 'reverted' | ..., logs: [...] } as the network returns it.
export function checkChain({ chainReceipt, chain, order }) {
  if (!chainReceipt) return step('chain', 'skip', `not checked here: look up ${order?.txHash ?? 'the transaction'} on the network`)
  if (chainReceipt.status !== 'success') return step('chain', 'fail', 'the transaction did not succeed on the network')
  const f = findPayment({ logs: chainReceipt.logs, token: chain.token, payer: chain.payer, payee: chain.payee, amountMicro: toMicro(order.amount), memo: order.id })
  return f.ok
    ? step('chain', 'pass', `the network shows ${order.amount} ${order.currency} from ${chain.payer.slice(0, 10)}… to ${chain.payee.slice(0, 10)}… with memo ${order.id}`)
    : step('chain', 'fail', f.reason)
}

// Turns what a JSON-RPC node returns for eth_getTransactionReceipt into the shape checkChain expects.
export const chainReceiptFromRpc = (result) => (result ? { status: result.status === '0x1' ? 'success' : 'reverted', logs: result.logs ?? [] } : { status: 'not found', logs: [] })

// ── a whole bundle ──────────────────────────────────────────────────────────────────────────────────────────
// opts: { oidcJwks (use these Keycloak keys instead of the bundle's), chainReceipt }
export async function verifyBundle(bundle, opts = {}) {
  const steps = []
  const add = (s) => { steps.push(s); return s.status !== 'fail' }
  try {
    const { order, mandates, request, receipts, grant, approval, chain, keys } = bundle ?? {}
    if (bundle?.version !== EVIDENCE_VERSION || !order || !mandates?.open || !mandates?.closed || !receipts?.mandate || !keys?.user || !keys?.agent || !keys?.store) {
      return finish([step('structure', 'fail', 'not an Agent Pay evidence bundle, or parts are missing')])
    }
    add(step('structure', 'pass', `order ${order.id}: ${order.item ?? order.sku} for ${order.amount} ${order.currency} at ${order.merchant}`))
    add(await checkMandateReceipt({ receipt: receipts.mandate, storeJwk: keys.store.jwk, closedJws: mandates.closed }))
    add(await checkPaymentReceipt({ receipt: receipts.payment, storeJwk: keys.store.jwk, closedJws: mandates.closed, order }))

    const openStep = await checkOpenMandate({ openJws: mandates.open, userJwk: keys.user.jwk, userSub: keys.user.sub, agentId: keys.agent.id, order })
    add(openStep)
    if (openStep.status === 'fail' && openStep.detail.startsWith('signature:')) return finish(steps)
    const om = decodeJws(mandates.open).payload

    add(await checkClosedMandate({ closedJws: mandates.closed, openJws: mandates.open, order, agentKid: keys.agent.kid }))
    add(checkLimits({ openPayload: om, order }))
    add(await checkAgentRequest({ request, lookupKey: (id) => (id === keys.agent.kid ? keys.agent.jwk : null) }))

    const oidc = opts.oidcJwks ? { ...keys.oidc, jwks: opts.oidcJwks } : keys.oidc
    add(await checkProof({ name: 'mandate_grant_proof', proof: grant?.proof, terms: await termsFromOpenMandate(om), expectSub: om.iss, at: om.iat, jwks: oidc?.jwks, issuer: oidc?.issuer, audience: oidc?.audience }))

    if (!approval) add(step('approval_proof', 'skip', 'autonomous purchase: the mandate alone authorized it, no per-purchase approval was required'))
    else {
      const want = orderOf({ merchant: order.merchant, sku: order.sku, amount: order.amount, currency: order.currency })
      const terms = approvalTerms({ approvalId: approval.id, orderHash: await orderHash(want), mandateId: om.jti })
      const decided = Math.floor(Date.parse(approval.decidedAt) / 1000)
      add(await checkProof({ name: 'approval_proof', proof: approval.proof, terms, expectSub: om.iss, at: decided, jwks: oidc?.jwks, issuer: oidc?.issuer, audience: oidc?.audience }))
    }

    add(checkChain({ chainReceipt: opts.chainReceipt, chain, order }))
  } catch (e) {
    steps.push(step('error', 'fail', `could not check the bundle: ${e.message}`))
  }
  return finish(steps)
}

export function finish(steps) {
  return { ok: steps.every((s) => s.status !== 'fail'), proven: steps.every((s) => s.status === 'pass' || s.status === 'skip'), steps }
}
