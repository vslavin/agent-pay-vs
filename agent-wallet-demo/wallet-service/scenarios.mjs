import { readFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { verifyJws, decodeJws, MANDATE_RECEIPT_TYP, PAYMENT_RECEIPT_TYP } from './mandate.mjs'

// Plays an agent against a store's checkout and checks that every attempt gets the answer it should.
//   node scenarios.mjs --store https://<domain>/shop/vsemporium --agent agt_xxxxxxxxxxxx
// It uses the wallet service (local, with its token) the way an agent runtime would: to sign requests with the
// agent's key and to sign closed mandates. It also creates short-lived test mandates for the agent, standing in
// for the user's passkey-approved step in the app. Nothing is paid: a successful checkout only quotes a price.

const { values: opts } = parseArgs({ options: {
  store: { type: 'string' }, agent: { type: 'string' }, service: { type: 'string', default: 'http://127.0.0.1:3100' },
  sub: { type: 'string' }, 'token-file': { type: 'string' }, only: { type: 'string' }, pay: { type: 'boolean', default: false },
} })
if (!opts.store || !opts.agent) { console.error('usage: node scenarios.mjs --store <store url> --agent <agt_id> [--sub <owner sub>] [--service <url>] [--only <n>] [--pay]'); process.exit(2) }

const tokenFile = opts['token-file'] ?? `${process.env.WALLET_DATA_DIR ?? new URL('./data', import.meta.url).pathname}/service-token`
const token = readFileSync(tokenFile, 'utf8').trim()
const svc = async (method, path, body) => {
  const r = await fetch(opts.service + path, { method, headers: { 'x-wallet-token': token, 'content-type': 'application/json' }, body: body && JSON.stringify(body) })
  return { status: r.status, json: await r.json().catch(() => null) }
}

const store = new URL(opts.store)
const username = store.pathname.split('/').filter(Boolean)[1]
const otherStore = ((await svc('GET', '/merchants')).json?.merchants ?? []).map((m) => m.username).find((u) => u !== store.pathname.split('/').filter(Boolean)[1])
const catalog = await (await fetch(`${store.origin}/shop/${username}/catalog.json`, { headers: { 'ngrok-skip-browser-warning': '1' } })).json()
const payTo = catalog.payment.payTo
const product = (i) => catalog.products[i]
const orderFor = (p) => ({ amount: p.price, currency: 'OUSD', merchant: username, quantity: 1, sku: p.sku })

async function newMandate({ merchants = [username], maxPerPurchase = '150', budget = '300', hours = 1 } = {}) {
  const sub = opts.sub ?? 'scenario-user'
  const r = await svc('POST', '/mandates', { sub, agentId: opts.agent, merchants, maxPerPurchase, budget, hours })
  if (r.status !== 200) throw new Error(`could not create a test mandate: ${JSON.stringify(r.json)}`)
  const list = await svc('GET', `/agents/${opts.agent}/mandates`)
  return { id: r.json.id, sub, jws: list.json.mandates.find((m) => m.id === r.json.id).jws }
}
const closedFor = async (openJws, p) => (await svc('POST', `/agents/${opts.agent}/closed-mandate`, { openJws, order: orderFor(p), payee: payTo })).json?.jws
const signedHeaders = async () => (await svc('POST', '/agents/sign', { agentId: opts.agent, authority: store.host, path: `/shop/${username}/checkout`, tag: 'agent-payer-auth' })).json.headers

async function checkout({ sku, mandates, headers }) {
  const res = await fetch(`${store.origin}/shop/${username}/checkout`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'ngrok-skip-browser-warning': '1', ...headers },
    body: JSON.stringify({ sku, mandates }),
  })
  return { http: res.status, body: await res.json().catch(() => ({})) }
}
const buy = async (p, mandate, { sign = true, closedFor: closedProduct = p } = {}) =>
  checkout({ sku: p.sku, headers: sign ? await signedHeaders() : {}, mandates: { open: mandate?.jws, closed: mandate ? await closedFor(mandate.jws, closedProduct) : undefined } })

const mode = catalog.payment.checkout.purchaseMode
const autonomous = [
  { name: 'Buy within the mandate', expect: [402, 'authorized'], run: async () => buy(product(0), await newMandate()) },
  { name: 'Agent presents no mandate at all', expect: [403, 'open_mandate'], run: async () => buy(product(0), null) },
  { name: 'Request is not signed (not a known agent)', expect: [401, 'agent_signature'], run: async () => buy(product(0), await newMandate(), { sign: false }) },
  { name: 'Price above the per-purchase limit', expect: [403, 'amount_in_range'], run: async () => buy(product(11), await newMandate({ maxPerPurchase: '150' })) },
  { name: 'Closed mandate signed for a different product', expect: [403, 'closed_mandate'], run: async () => buy(product(1), await newMandate(), { closedFor: product(0) }) },
  { name: 'Store not on the mandate (the mandate allows a different store)', expect: [403, 'payee_allowed'], needsOtherStore: true,
    run: async () => buy(product(0), await newMandate({ merchants: [otherStore] })) },
  { name: 'Mandate revoked by the user', expect: [403, 'mandate_active'], run: async () => { const m = await newMandate(); await svc('POST', `/mandates/${m.id}/revoke`, { sub: m.sub }); return buy(product(0), m) } },
  { name: 'Replaying a signed request', expect: [401, 'agent_signature'], run: async () => {
    const m = await newMandate(); const headers = await signedHeaders()
    const body = { sku: product(0).sku, mandates: { open: m.jws, closed: await closedFor(m.jws, product(0)) } }
    const send = () => fetch(`${store.origin}/shop/${username}/checkout`, { method: 'POST', headers: { 'content-type': 'application/json', 'ngrok-skip-browser-warning': '1', ...headers }, body: JSON.stringify(body) })
    await send(); const second = await send(); return { http: second.status, body: await second.json() } } },
  { name: 'Spending the whole budget, then one purchase too many', expect: [403, 'budget_available'], run: async () => {
    const m = await newMandate({ budget: '200', maxPerPurchase: '150' })
    const a = await buy(product(0), m) // 89 of 200
    const b = await buy(product(4), m) // 110 -> 199 of 200
    const c = await buy(product(10), m) // 75 -> over budget
    c.note = `first two purchases: HTTP ${a.http} and ${b.http}`
    return c } },
]

// Human-present store: every purchase needs the user's passkey-approved yes to this exact cart.
// The approve/decline calls below stand in for the user's step in the app (which requires a fresh passkey sign-in).
const wide = { maxPerPurchase: '1000', budget: '3000' }
const approvalOf = (r) => r.body.approval?.id
const decide = (id, decision, sub = opts.sub ?? 'scenario-user', authTime = Math.floor(Date.now() / 1000)) => svc('POST', `/approvals/${id}/${decision}`, { sub, authTime })
const humanPresent = [
  { name: 'Valid mandate, but the user has not approved this cart', expect: [403, 'purchase_mode'], run: async () => {
    const r = await buy(product(0), await newMandate(wide)); r.note = `approval ${approvalOf(r)} is ${r.body.approval?.status}; the agent must wait for the user`; return r } },
  { name: 'Asking again reuses the same pending approval', expect: [403, 'purchase_mode'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m); const b = await buy(product(0), m)
    b.note = approvalOf(a) === approvalOf(b) ? `same approval ${approvalOf(a)}` : 'a second approval was opened (wrong)'
    if (approvalOf(a) !== approvalOf(b)) b.body.code = 'duplicate_approval'
    return b } },
  { name: 'User approves with a fresh passkey sign-in; the agent retries', expect: [402, 'authorized'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m)
    await decide(approvalOf(a), 'approve'); return buy(product(0), m) } },
  { name: 'Approval is single-use: a second identical purchase needs a new approval', expect: [403, 'purchase_mode'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m)
    await decide(approvalOf(a), 'approve'); await buy(product(0), m); return buy(product(0), m) } },
  { name: 'Approval for one watch does not unlock a different watch', expect: [403, 'purchase_mode'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m)
    await decide(approvalOf(a), 'approve'); return buy(product(1), m) } },
  { name: 'User declines the purchase', expect: [403, 'purchase_mode'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m)
    await decide(approvalOf(a), 'reject'); const r = await buy(product(0), m); r.note = r.body.reason; return r } },
  { name: 'Approval without a fresh sign-in is refused by the wallet service', expect: [403, 'purchase_mode'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m)
    const stale = await decide(approvalOf(a), 'approve', undefined, Math.floor(Date.now() / 1000) - 3600)
    const r = await buy(product(0), m); r.note = `approve call: HTTP ${stale.status} (${stale.json?.error})`; return r } },
  { name: 'Someone else cannot approve the agent’s cart', expect: [403, 'purchase_mode'], run: async () => {
    const m = await newMandate(wide); const a = await buy(product(0), m)
    const other = await decide(approvalOf(a), 'approve', 'another-user')
    const r = await buy(product(0), m); r.note = `approve call by another user: HTTP ${other.status}`; return r } },
  { name: 'Price above the per-purchase limit is refused before any approval is asked', expect: [403, 'amount_in_range'], run: async () => buy(product(7), await newMandate({ maxPerPurchase: '1000', budget: '3000' })) },
]

// Payment: after a quote, the user's wallet pays on Tempo testnet and the store confirms from the chain.
// Needs --pay (it spends test OUSD from the owner's wallet: --sub must have a wallet with enough balance).
const receiptKey = catalog.merchant.receiptKey
const payCheck = (r) => (r.http === 402 ? r.body : null)
async function quote(p, m) {
  if (mode === 'human_present') {
    const a = await buy(p, m); if (approvalOf(a)) await decide(approvalOf(a), 'approve')
  }
  return buy(p, m)
}
const payOrder = (orderId, agent = opts.agent) => svc('POST', `/agents/${agent}/pay`, { orderId })
const confirmAtStore = async (orderId, txHash) => { const r = await fetch(`${store.origin}/shop/${username}/orders/${orderId}/confirm`, { method: 'POST', headers: { 'content-type': 'application/json', 'ngrok-skip-browser-warning': '1' }, body: JSON.stringify({ txHash }) }); return { http: r.status, body: await r.json().catch(() => ({})) } }
const orderAtStore = async (orderId) => (await fetch(`${store.origin}/shop/${username}/orders/${orderId}`, { headers: { 'ngrok-skip-browser-warning': '1' } })).json()
const wide2 = { maxPerPurchase: '3000', budget: '9000' }
const cheap = () => (mode === 'human_present' ? product(0) : product(10))   // 420 OUSD watch, or the 75 OUSD sneaker
const paymentScenarios = [
  { name: 'Pay the quote: on-chain transfer, store confirms, both receipts verify', expect: [200, 'paid'], run: async () => {
    const m = await newMandate(wide2); const q = await quote(cheap(), m); const q1 = payCheck(q); if (!q1) return q
    const mr = verifyJws(q1.receipts.mandate, receiptKey, MANDATE_RECEIPT_TYP)
    const paid = await payOrder(q1.orderId)
    const o = await orderAtStore(q1.orderId)
    const pr = o.receipts?.payment ? verifyJws(o.receipts.payment, receiptKey, PAYMENT_RECEIPT_TYP) : { ok: false }
    const chainTx = paid.json?.txHash
    let onChain   // the chain's log index can lag a moment behind the receipt; the same transaction also lists the network fee
    for (let i = 0; i < 6 && !onChain; i++) {
      if (i) await new Promise((r) => setTimeout(r, 2000))
      const hist = await svc('GET', `/wallets/${encodeURIComponent(opts.sub ?? 'scenario-user')}`)
      onChain = hist.json?.history?.find((t) => t.hash === chainTx && t.memo === q1.orderId)
    }
    const checks = { 'mandate receipt verifies and says success': mr.ok && mr.payload.result === 'success',
      'order is paid': o.status === 'paid', 'payment receipt verifies and says Success': pr.ok && pr.payload.status === 'Success',
      'both receipts reference the same closed mandate': pr.ok && mr.ok && pr.payload.reference === mr.payload.reference,
      'receipt names the order and the transaction': pr.ok && pr.payload.payment_id === q1.orderId && pr.payload.network_confirmation_id === chainTx,
      'transfer on-chain carries the order id as memo, outgoing, right amount': onChain?.memo === q1.orderId && onChain?.direction === 'out' && onChain?.amount === q1.payment.amount }
    const bad = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k)
    return { http: paid.status, body: { code: bad.length ? 'not_paid' : 'paid', reason: bad.length ? `failed: ${bad.join('; ')}` : undefined, note: `tx ${chainTx}` }, note: `order ${q1.orderId}, tx ${chainTx}` }
  } },
  { name: 'Paying the same order twice does not pay twice', expect: [200, 'paid_once'], run: async () => {
    const m = await newMandate(wide2); const q1 = payCheck(await quote(cheap(), m)); if (!q1) return { http: 0, body: { code: 'no_quote' } }
    const a = await payOrder(q1.orderId); const b = await payOrder(q1.orderId)
    const same = a.json?.txHash && a.json.txHash === b.json?.txHash && b.json?.already === true
    return { http: b.status, body: { code: same ? 'paid_once' : 'paid_twice', reason: same ? undefined : JSON.stringify(b.json) } } } },
  { name: 'Mandate revoked between quote and payment: the wallet refuses', expect: [403, 'refused'], run: async () => {
    const m = await newMandate(wide2); const q1 = payCheck(await quote(cheap(), m)); if (!q1) return { http: 0, body: { code: 'no_quote' } }
    await svc('POST', `/mandates/${m.id}/revoke`, { sub: m.sub })
    const r = await payOrder(q1.orderId); const o = await orderAtStore(q1.orderId)
    return { http: r.status, body: { code: o.status === 'payment_required' ? 'refused' : `order is ${o.status}`, reason: r.json?.error } } } },
  { name: 'A transaction that paid one order cannot confirm another', expect: [409, 'not_this_order'], run: async () => {
    const m = await newMandate(wide2); const a = payCheck(await quote(cheap(), m)); const b = payCheck(await quote(cheap(), m)); if (!a || !b) return { http: 0, body: { code: 'no_quote' } }
    const paid = await payOrder(a.orderId); const r = await confirmAtStore(b.orderId, paid.json.txHash)
    return { http: r.http, body: { code: r.body.code === 'not_confirmed' ? 'not_this_order' : r.body.code, reason: r.body.reason } } } },
  { name: 'An expired quote cannot be paid and stops counting against the budget', expect: [409, 'expired'], needsShortQuote: true, run: async () => {
    const m = await newMandate({ maxPerPurchase: '500', budget: '600' }); const q1 = payCheck(await quote(cheap(), m)); if (!q1) return { http: 0, body: { code: 'no_quote' } }
    await new Promise((r) => setTimeout(r, Math.max(0, Date.parse(q1.payment.expiresAt) - Date.now()) + 500))
    const r = await payOrder(q1.orderId); const o = await orderAtStore(q1.orderId)
    const view = (await svc('GET', `/mandates?sub=${encodeURIComponent(m.sub)}`)).json.mandates.find((x) => x.id === m.id)
    return { http: r.status, body: { code: o.status === 'expired' && Number(view.spent) === 0 ? 'expired' : `order ${o.status}, spent ${view.spent}`, reason: r.json?.error } } } },
  { name: 'Another agent cannot pay this order', expect: [404, 'refused'], run: async () => {
    const m = await newMandate(wide2); const q1 = payCheck(await quote(cheap(), m)); if (!q1) return { http: 0, body: { code: 'no_quote' } }
    const r = await payOrder(q1.orderId, 'agt_ffffffffffff'); return { http: r.status, body: { code: 'refused', reason: r.json?.error } } } },
]
const scenarios = opts.pay ? paymentScenarios : mode === 'human_present' ? humanPresent : autonomous

const only = opts.only ? Number(opts.only) : null
let failures = 0
console.log(`Agent ${opts.agent} vs ${store.origin}/shop/${username}  (purchase mode: ${mode}${opts.pay ? ', payment scenarios: real testnet transfers' : ''})\n`)
for (const [i, s] of scenarios.entries()) {
  if (only && only !== i + 1) continue
  if (s.needsShortQuote && Date.parse((await quote(cheap(), await newMandate(wide2)).then((r) => r.body?.payment?.expiresAt ?? 0))) - Date.now() > 30_000) { console.log(`${String(i + 1).padStart(2)}. ${s.name}\n    skipped: start the wallet service with WALLET_QUOTE_TTL_SECONDS=3 to run this one\n`); continue }
  if (s.needsOtherStore && !otherStore) { console.log(`${String(i + 1).padStart(2)}. ${s.name}\n    skipped: needs a second store\n`); continue }
  let out
  try { out = await s.run() } catch (e) { out = { http: 0, body: { code: 'error', reason: e.message } } }
  const code = out.body.status === 'payment_required' ? 'authorized' : out.body.code
  const ok = out.http === s.expect[0] && code === s.expect[1]
  if (!ok) failures++
  console.log(`${String(i + 1).padStart(2)}. ${s.name}\n    expected HTTP ${s.expect[0]} (${s.expect[1]}); got HTTP ${out.http} (${code})  ${ok ? 'PASS' : 'FAIL'}`)
  if (out.body.reason) console.log(`    reason: ${out.body.reason}`)
  if (out.body.payment) console.log(`    quote: pay ${out.body.payment.amount} ${out.body.payment.currency} to ${out.body.payment.payTo.slice(0, 10)}… ref ${out.body.payment.reference}`)
  if (out.note) console.log(`    note: ${out.note}`)
  console.log()
}
console.log(failures ? `${failures} scenario(s) did not behave as expected.` : 'Every scenario behaved as expected.')
process.exit(failures ? 1 : 0)
