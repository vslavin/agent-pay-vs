// Check Receipt: the page. All checking is in verify.js; this file collects the pieces, runs the checks, and explains
// each one. State lives in one object, S. Every input writes into it and every result is recomputed from it, so loading
// a whole bundle and typing the pieces in one at a time go through exactly the same code.
import * as V from './verify.js'

const $ = (sel, root = document) => root.querySelector(sel)
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v == null || v === false) continue
    if (k === 'class') e.className = v
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v)
    else e.setAttribute(k, v === true ? '' : v)
  }
  for (const kid of kids.flat()) e.append(kid?.nodeType ? kid : document.createTextNode(kid ?? ''))
  return e
}

// ── state ──────────────────────────────────────────────────────────────────────────────────────────────────
const blank = () => ({
  order: { merchant: '', sku: '', item: '', amount: '', currency: 'OUSD', id: '', status: '', createdAt: '', txHash: '' },
  orderJson: '', orderUrl: '',
  open: '', userJwk: '', userSub: '', closed: '',
  mandateReceipt: '', paymentReceipt: '', storeJwk: '',
  req: { authority: '', path: '', sigInput: '', signature: '' },
  oidc: { issuer: '', audience: '', jwks: '' }, grantToken: '', grantDev: false,
  approval: { id: '', decidedAt: '', token: '' },
  chain: { rpc: '', token: '', payer: '', payee: '', receiptJson: '' },
  agent: null,                                   // { id, kid, jwk } when a bundle supplied it
  src: { userJwk: '', storeJwk: '', jwks: '' },  // where each key came from: 'bundle' | 'you' | 'host:<name>' | 'button'
  example: false,
})
let S = blank()
let original = null
let mode = null
const getp = (k) => k.split('.').reduce((o, p) => o?.[p], S)
const setp = (k, v) => { const ps = k.split('.'); const last = ps.pop(); ps.reduce((o, p) => o[p], S)[last] = v }
const PROV = { userJwk: 'userJwk', storeJwk: 'storeJwk', 'oidc.jwks': 'jwks' }

// ── small parsers ───────────────────────────────────────────────────────────────────────────────────────────
const tok = (t) => String(t ?? '').trim().replace(/^["'\s]+|["',\s]+$/g, '').replace(/\s+/g, '')
const jsonOf = (t) => { const s = String(t ?? '').trim(); if (!s) return { empty: true }; try { return { value: JSON.parse(s) } } catch { return { error: 'that is not valid JSON' } } }
const edKey = (text) => {
  const j = jsonOf(text)
  if (j.empty || j.error) return j
  const k = j.value?.jwk ?? j.value
  return k?.kty === 'OKP' && k?.crv === 'Ed25519' && typeof k.x === 'string' ? { value: k } : { error: 'that is not an Ed25519 public key (it should say "kty": "OKP" and "crv": "Ed25519")' }
}
const jwksOf = (text) => {
  const j = jsonOf(text)
  if (j.empty || j.error) return j
  return Array.isArray(j.value?.keys) ? { value: j.value } : { error: 'that is not a key set (it should look like {"keys": [ … ]})' }
}
const stripHeader = (t) => String(t ?? '').trim().replace(/^signature(-input)?\s*:\s*/i, '')
const validDate = (t) => Boolean(t) && !Number.isNaN(Date.parse(t))
const when = (sec) => `${new Date(sec * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '')} UTC`
const short = (t, n = 12) => (t && t.length > n + 1 ? `${t.slice(0, n)}…` : t)
const hostOf = (u) => { try { return new URL(u).host } catch { return '' } }

// ── the cards: what each link proves, what it needs, where to find it ───────────────────────────────────────
const LINKS = {
  open_mandate: ['The user’s mandate', 'open'], closed_mandate: ['The agent’s mandate', 'closed'], limits: ['Inside the user’s limits', 'closed'],
  mandate_receipt: ['Store’s mandate receipt', 'receipts'], payment_receipt: ['Store’s payment receipt', 'receipts'],
  agent_request: ['The agent’s signed request', 'request'], mandate_grant_proof: ['Sign-in for the mandate', 'proofs'], approval_proof: ['Sign-in for this purchase', 'proofs'],
  chain: ['Payment on the network', 'chain'],
}
const F = (key, label, o = {}) => ({ key, label, ...o })
const CARDS = [
  { id: 'order', title: 'The purchase', q: 'What is this receipt about?', results: [],
    proves: 'This is the order everything else is compared against. If a signature was made for a different item, price or store, the later steps will not match it.',
    where: 'On a receipt page, use the raw data (JSON) link and paste it below, or fetch it from its address. In an evidence bundle this is the “order” section.',
    custom: 'order',
    fields: [
      [F('order.merchant', 'Store (username)', { ph: 'luxe' }), F('order.sku', 'Item code', { ph: 'LUX-001' })],
      [F('order.amount', 'Price', { ph: '420' }), F('order.currency', 'Currency', { ph: 'OUSD' })],
      [F('order.id', 'Order id', { ph: 'ord_…' }), F('order.status', 'Status', { kind: 'select', opts: [['', 'not sure'], ['paid', 'paid'], ['payment_required', 'quote, not paid'], ['failed', 'payment failed'], ['expired', 'quote expired']] })],
      [F('order.createdAt', 'Created at', { ph: '2026-11-14T18:00:00.000Z', help: 'Optional: checks that the order was made while the mandate was valid.' }), F('order.txHash', 'Transaction hash', { ph: '0x…', help: 'Only for paid orders.' })],
    ] },
  { id: 'open', title: 'What the user allowed', q: 'The open mandate', results: ['open_mandate'],
    proves: 'A mandate is a permission slip. The user signs it with their own key and says: this agent may buy from these stores, up to this much per purchase and this much in total, until this time. If the signature checks out, whoever holds that key said exactly this, and nobody can change a word without breaking it. The mandate also names the agent’s key, so it works for that one agent only.',
    where: 'In the bundle: “mandates.open” (a long text starting with eyJ) and “keys.user.jwk”.',
    fields: [
      [F('open', 'Open mandate', { kind: 'area', rows: 3, ph: 'eyJhbGciOiJFZERTQSIs…' })],
      [F('userJwk', 'The user’s public key', { kind: 'area', rows: 3, ph: '{"kty":"OKP","crv":"Ed25519","x":"…"}', prov: 'userJwk', help: 'Optional extra: the user id below is compared with the mandate’s issuer.' })],
      [F('userSub', 'User id (optional)', { ph: 'the account id this mandate should be from' })],
    ] },
  { id: 'closed', title: 'What the agent committed to', q: 'The closed mandate', results: ['closed_mandate', 'limits'],
    proves: 'For one particular purchase the agent signs a second, narrower document: this order, this payee, this amount. It carries a fingerprint of the open mandate, so it cannot be moved to another mandate, and it is signed with the agent key the open mandate named, so you do not need to be given that key: it comes from step 2. Then the order is compared with the user’s limits.',
    where: 'In the bundle: “mandates.closed”.',
    custom: 'closed',
    fields: [[F('closed', 'Closed mandate', { kind: 'area', rows: 3, ph: 'eyJhbGciOiJFZERTQSIs…' })]] },
  { id: 'receipts', title: 'What the store accepted', q: 'The store’s receipts', results: ['mandate_receipt', 'payment_receipt'],
    proves: 'The store signs a receipt when it accepts the agent’s mandate and another when the payment arrives. Each carries a fingerprint of the closed mandate, so the store cannot later claim it saw something else. They are signed with the store’s own key, which it publishes in its catalog.',
    where: 'In the bundle: “receipts.mandate” and “receipts.payment”, and the store’s key in “keys.store.jwk”. A public receipt’s raw data has the two receipts too.',
    custom: 'receipts',
    fields: [
      [F('mandateReceipt', 'Mandate receipt', { kind: 'area', rows: 3, ph: 'eyJ…' })],
      [F('paymentReceipt', 'Payment receipt (only if paid)', { kind: 'area', rows: 3, ph: 'eyJ…' })],
      [F('storeJwk', 'The store’s public key', { kind: 'area', rows: 3, ph: '{"kty":"OKP","crv":"Ed25519","x":"…"}', prov: 'storeJwk' })],
    ] },
  { id: 'request', title: 'Who called the store', q: 'The agent’s signed request', results: ['agent_request'],
    proves: 'When the agent asked to buy, it signed the web request itself (an HTTP message signature, as in Visa’s Trusted Agent Protocol) with the same key the mandate names. That shows which agent called, which address it called, and when.',
    where: 'In the bundle: the “request” section.',
    fields: [
      [F('req.authority', 'Store address (host)', { ph: 'shop.example' }), F('req.path', 'Path', { ph: '/shop/luxe/checkout' })],
      [F('req.sigInput', 'Signature-Input header', { kind: 'area', rows: 3, ph: 'sig2=("@authority" "@path");created=…' })],
      [F('req.signature', 'Signature header', { kind: 'area', rows: 2, ph: 'sig2=:…:' })],
    ] },
  { id: 'proofs', title: 'Did the person really say yes?', q: 'The sign-in proofs', results: ['mandate_grant_proof', 'approval_proof'],
    proves: 'Everything above is signed by keys. This step asks whether the human was behind them. To grant a mandate (and to approve a single purchase at the stricter stores) the person signs in again. The app puts a fingerprint of the exact terms into that sign-in, and Keycloak signs the resulting ID token. So its signature shows that this account signed in, just then, for these terms and no others.',
    where: 'In the bundle: “grant.proof.idToken”, “approval” (for stores that ask per purchase) and “keys.oidc” for Keycloak’s keys.',
    custom: 'proofs',
    fields: [
      [F('oidc.issuer', 'Keycloak realm (issuer)', { ph: 'https://login.example/realms/demo' }), F('oidc.audience', 'Audience (client id)', { ph: 'demo-app', help: 'The Agent Pay demo uses demo-app.' })],
      [F('oidc.jwks', 'Keycloak’s public keys', { kind: 'area', rows: 3, ph: '{"keys":[ … ]}', prov: 'jwks' })],
      [F('grantToken', 'ID token from granting the mandate', { kind: 'area', rows: 3, ph: 'eyJhbGciOiJSUzI1NiIs…' })],
      [F('approval.id', 'Approval id (only for per-purchase approval)', { ph: 'apr_…' }), F('approval.decidedAt', 'Approved at', { ph: '2026-11-14T18:00:08.000Z' })],
      [F('approval.token', 'ID token from approving this purchase', { kind: 'area', rows: 3, ph: 'eyJhbGciOiJSUzI1NiIs…' })],
    ] },
  { id: 'chain', title: 'Did the money move?', q: 'The transfer on the network', results: ['chain'],
    proves: 'The payment is a transfer on a public network, so anyone can look it up. It must come from the buyer’s wallet, go to the store, be for the right amount and carry the order id as its memo. All four have to be true of the same transfer.',
    where: 'In the bundle: the “chain” section. Look the transaction up with the button, or paste what a node returns for eth_getTransactionReceipt.',
    custom: 'chain',
    fields: [
      [F('chain.rpc', 'Network node (RPC address)', { ph: 'https://rpc.example' })],
      [F('chain.token', 'Token contract', { ph: '0x…' })],
      [F('chain.payer', 'Buyer’s wallet', { ph: '0x…' }), F('chain.payee', 'Store’s wallet', { ph: '0x…' })],
      [F('chain.receiptJson', 'Transaction receipt (JSON)', { kind: 'area', rows: 4, ph: '{"status":"0x1","logs":[ … ]}' })],
    ] },
]

// ── computing the results ───────────────────────────────────────────────────────────────────────────────────
const todo = (detail) => ({ status: 'todo', detail })
const bad = (detail) => ({ status: 'fail', detail })
const normaliseChain = (v) => {
  if (v && typeof v === 'object' && 'result' in v && v.result === null) return { status: 'not found', logs: [] }
  const r = v?.result ?? v
  if (r && typeof r.status === 'string' && r.status.startsWith('0x')) return V.chainReceiptFromRpc(r)
  if (r && ['success', 'reverted', 'not found'].includes(r.status) && Array.isArray(r.logs)) return r
  return null
}

async function compute() {
  const R = {}, D = {}   // results by step name; decoded pieces for the “what’s inside” views
  const o = S.order
  const full = o.merchant.trim() && o.sku.trim() && o.amount.trim() && o.currency.trim()
    ? { merchant: o.merchant.trim(), sku: o.sku.trim(), amount: o.amount.trim(), currency: o.currency.trim(), id: o.id.trim(), status: o.status, createdAt: o.createdAt.trim(), txHash: o.txHash.trim() } : null

  // 2. open mandate
  const open = tok(S.open), uk = edKey(S.userJwk)
  const openDecoded = open ? V.decodeJws(open) : null
  D.open = openDecoded
  if (!open) R.open_mandate = todo('Waiting for the open mandate.')
  else if (!openDecoded) R.open_mandate = bad('That does not look like a mandate. It should be three blocks of letters and digits joined by dots.')
  else if (uk.empty) R.open_mandate = todo('Waiting for the user’s public key.')
  else if (uk.error) R.open_mandate = bad(`The user’s key: ${uk.error}.`)
  else R.open_mandate = await V.checkOpenMandate({ openJws: open, userJwk: uk.value, userSub: S.userSub.trim() || undefined, agentId: S.agent?.id, order: validDate(o.createdAt) ? { createdAt: o.createdAt.trim() } : null })
  const openUsable = Boolean(openDecoded) && !uk.empty && !uk.error && !(R.open_mandate.status === 'fail' && R.open_mandate.detail.startsWith('signature:'))
  const agentJwk = S.agent?.jwk ?? openDecoded?.payload?.cnf?.jwk
  const agentKid = S.agent?.kid ?? (agentJwk ? await V.thumbprint(agentJwk) : null)
  D.agentKid = agentKid

  // 3. closed mandate and limits
  const closed = tok(S.closed)
  D.closed = closed ? V.decodeJws(closed) : null
  if (!closed) R.closed_mandate = todo('Waiting for the closed mandate.')
  else if (!openUsable) R.closed_mandate = todo('Needs a valid open mandate first (step 2): it names the agent’s key.')
  else R.closed_mandate = await V.checkClosedMandate({ closedJws: closed, openJws: open, order: full, agentKid: S.agent?.kid })
  if (!openUsable) R.limits = todo('Needs the open mandate (step 2) and the order (step 1).')
  else if (!full) R.limits = todo('Needs the order’s store, item, price and currency (step 1).')
  else R.limits = V.checkLimits({ openPayload: openDecoded.payload, order: full })

  // 4. receipts
  const mr = tok(S.mandateReceipt), pr = tok(S.paymentReceipt), sk = edKey(S.storeJwk)
  D.mr = mr ? V.decodeJws(mr) : null
  D.pr = pr ? V.decodeJws(pr) : null
  const keyWait = sk.empty ? todo('Waiting for the store’s public key.') : sk.error ? bad(`The store’s key: ${sk.error}.`) : null
  const closedArg = closed || undefined
  R.mandate_receipt = !mr ? todo('Waiting for the mandate receipt.') : keyWait ?? await V.checkMandateReceipt({ receipt: mr, storeJwk: sk.value, closedJws: closedArg })
  if (!pr && o.status !== 'paid') R.payment_receipt = { status: 'skip', detail: o.status ? `The order is not paid (${o.status}), so there is no payment receipt.` : 'Optional: only a paid order has a payment receipt.' }
  else R.payment_receipt = keyWait ?? await V.checkPaymentReceipt({ receipt: pr || null, storeJwk: sk.value, closedJws: closedArg, order: { id: o.id.trim() || undefined, txHash: o.txHash.trim() || undefined, status: o.status || undefined } })

  // 5. the agent's signed request
  const q = S.req
  if (!(q.authority.trim() && q.path.trim() && q.sigInput.trim() && q.signature.trim())) R.agent_request = todo('Waiting for the agent’s signed request (host, path and the two signature headers).')
  else if (!agentJwk) R.agent_request = todo('Needs the open mandate (step 2): it names the agent’s key.')
  else R.agent_request = await V.checkAgentRequest({ request: { authority: q.authority.trim(), path: q.path.trim(), headers: { 'signature-input': stripHeader(q.sigInput), signature: stripHeader(q.signature) } }, lookupKey: (id) => (id === agentKid ? agentJwk : null) })

  // 6. sign-in proofs
  const jw = jwksOf(S.oidc.jwks), iss = S.oidc.issuer.trim(), aud = S.oidc.audience.trim()
  const oidcWait = !iss || !aud ? todo('Waiting for Keycloak’s issuer and audience.') : jw.empty ? todo('Waiting for Keycloak’s public keys.') : jw.error ? bad(`Keycloak’s keys: ${jw.error}.`) : null
  const gt = tok(S.grantToken), at = tok(S.approval.token)
  D.grant = gt ? V.decodeIdToken(gt) : null
  D.approvalTok = at ? V.decodeIdToken(at) : null
  let terms = null
  if (openUsable) { try { terms = V.termsFromOpenMandate(openDecoded.payload) } catch { terms = null } }
  D.terms = terms
  if (S.grantDev) R.mandate_grant_proof = await V.checkProof({ name: 'mandate_grant_proof', proof: { mode: 'dev-unproven' } })
  else if (!gt) R.mandate_grant_proof = todo('Waiting for the ID token from when the mandate was granted.')
  else if (!openUsable) R.mandate_grant_proof = todo('Needs the open mandate and the user’s key (step 2).')
  else if (!terms) R.mandate_grant_proof = bad('The mandate’s limits are not in the expected shape, so its terms cannot be rebuilt.')
  else R.mandate_grant_proof = oidcWait ?? await V.checkProof({ name: 'mandate_grant_proof', proof: { idToken: gt }, terms, expectSub: openDecoded.payload.iss, at: openDecoded.payload.iat, jwks: jw.value, issuer: iss, audience: aud })
  const ap = S.approval
  if (!(ap.id.trim() || ap.decidedAt.trim() || at)) R.approval_proof = { status: 'skip', detail: 'No per-purchase approval supplied. A store that accepts purchases on the mandate alone does not need one; a store that asks the person to approve each purchase does.' }
  else if (!(ap.id.trim() && validDate(ap.decidedAt) && at)) R.approval_proof = todo('Needs the approval id, the time it was approved and its ID token.')
  else if (!openUsable || !full) R.approval_proof = todo('Needs the open mandate (step 2) and the order (step 1).')
  else {
    const want = V.orderOf({ merchant: full.merchant, sku: full.sku, amount: full.amount, currency: full.currency })
    D.approvalTerms = V.approvalTerms({ approvalId: ap.id.trim(), orderHash: await V.orderHash(want), mandateId: openDecoded.payload.jti })
    R.approval_proof = oidcWait ?? await V.checkProof({ name: 'approval_proof', proof: { idToken: at }, terms: D.approvalTerms, expectSub: openDecoded.payload.iss, at: Math.floor(Date.parse(ap.decidedAt) / 1000), jwks: jw.value, issuer: iss, audience: aud })
  }
  if (terms) D.termsHash = await V.termsHash(terms)

  // 7. the transfer
  const c = S.chain, rj = jsonOf(c.receiptJson)
  if (!(c.token.trim() && c.payer.trim() && c.payee.trim())) R.chain = todo('Waiting for the token contract and the two wallet addresses.')
  else if (!full || !full.id) R.chain = todo('Needs the order id, store, item and price (step 1).')
  else if (rj.empty) R.chain = todo('Not looked up yet. Press “Look up on the network”, or paste the transaction receipt.')
  else if (rj.error) R.chain = bad(`The transaction receipt: ${rj.error}.`)
  else {
    const n = normaliseChain(rj.value)
    R.chain = n ? V.checkChain({ chainReceipt: n, chain: { token: c.token.trim(), payer: c.payer.trim(), payee: c.payee.trim() }, order: full }) : bad('That does not look like a transaction receipt (it should have a status and a list of logs).')
  }
  return { R, D, full }
}

// ── rendering ───────────────────────────────────────────────────────────────────────────────────────────────
const STATUS = { pass: ['✔', 'Checks out'], fail: ['✘', 'Does not hold'], warn: ['!', 'Holds, with a note'], skip: ['–', 'Not needed'], todo: ['○', 'Waiting'] }
const chip = (st, label) => h('span', { class: `chip ${st}` }, STATUS[st][0], ' ', label ?? STATUS[st][1])
const worst = (list) => list.some((s) => s === 'fail') ? 'fail' : list.some((s) => s === 'todo') ? 'todo' : list.some((s) => s === 'warn') ? 'warn' : list.some((s) => s === 'pass') ? 'pass' : 'skip'
const kv = (rows) => h('dl', { class: 'kv' }, rows.filter(Boolean).flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]))
const amt = (n, cur) => `${V.fromMicro(BigInt(n))} ${cur ?? ''}`.trim()
const openIds = new Set()
function inside(id, title, rows, raw) {
  const d = h('details', {}, h('summary', {}, title), rows ? kv(rows) : null, h('pre', {}, JSON.stringify(raw, null, 2)))
  d.open = openIds.has(id)
  d.addEventListener('toggle', () => (d.open ? openIds.add(id) : openIds.delete(id)))
  return d
}

function insideViews(id, D) {
  const out = []
  const safe = (fn) => { try { return fn() } catch { return null } }
  if (id === 'open' && D.open) {
    const p = D.open.payload
    const c = (t) => (p.constraints ?? []).find((x) => x.type === t) ?? {}
    out.push(inside('open', 'What is inside this mandate', safe(() => [
      ['Signed by (the user)', String(p.iss)], ['For the agent', String(p.sub)], ['Agent key fingerprint', short(D.agentKid, 16) ?? '—'],
      ['Stores it may pay', (c('payment.allowed_payees').allowed ?? []).map((x) => x.name ?? x.id).join(', ')],
      ['Most per purchase', amt(c('payment.amount_range').max, c('payment.amount_range').currency)], ['Total budget', amt(c('payment.budget').max, c('payment.budget').currency)],
      ['Valid from', when(p.iat)], ['Valid until', when(p.exp)], ['Mandate id', String(p.jti)],
    ]), p))
  }
  if (id === 'closed' && D.closed) {
    const p = D.closed.payload
    out.push(inside('closed', 'What is inside this mandate', safe(() => [
      ['Signed by', `the agent (key ${short(D.agentKid, 16) ?? 'not known yet'})`], ['Pays', `${p.payee?.id} at ${p.payee?.address}`], ['Amount', amt(p.payment_amount?.amount, p.payment_amount?.currency)],
      ['Fingerprint of the order', short(p.transaction_id, 20)], ['Fingerprint of the open mandate', short(p.open, 20)], ['Valid until', when(p.exp)],
    ]), p))
  }
  if (id === 'receipts') {
    for (const [k, t, d] of [['mr', 'Mandate receipt', D.mr], ['pr', 'Payment receipt', D.pr]]) {
      if (!d) continue
      const p = d.payload
      out.push(inside(k, `${t}: what is inside`, safe(() => [
        ['Issued by', String(p.iss)], ['At', when(p.iat)], ['Outcome', String(p.result ?? p.status)], ['Refers to closed mandate', short(p.reference, 20)],
        p.payment_id ? ['Order', String(p.payment_id)] : null, p.network_confirmation_id ? ['Transaction', short(p.network_confirmation_id, 20)] : null, p.error ? ['Error', `${p.error}: ${p.error_description ?? ''}`] : null,
      ]), p))
    }
  }
  if (id === 'proofs') {
    for (const [k, t, d] of [['grant', 'Mandate sign-in', D.grant], ['apr', 'Purchase sign-in', D.approvalTok]]) {
      if (!d) continue
      const p = d.claims
      out.push(inside(k, `${t}: what is inside the ID token`, safe(() => [
        ['Signed by', String(p.iss)], ['Account', String(p.sub)], ['Signed in at', when(p.auth_time)], ['Method', p.amr ? JSON.stringify(p.amr) : 'not recorded'], ['Terms fingerprint (nonce)', short(String(p.nonce), 20)],
      ]), p))
    }
    if (D.terms) out.push(inside('terms', 'The terms this page rebuilt from the mandate', [['Fingerprint', short(D.termsHash, 20)], ['Must equal', 'the mandate sign-in’s nonce above']], D.terms))
    if (D.approvalTerms) out.push(inside('aterms', 'The approval terms this page rebuilt', null, D.approvalTerms))
  }
  return out
}

let cardEls = {}, fieldEls = []
const PROVTEXT = (s) => !s ? null : s === 'bundle' ? ['from the bundle itself: not independent', 'weak'] : s === 'you' ? ['pasted by you', ''] : s === 'button' ? ['generated by the button', 'weak'] : s.startsWith('host:') ? [`fetched from ${s.slice(5)}`, 'good'] : null

function render({ R, D }) {
  for (const card of CARDS) {
    const el = cardEls[card.id]
    const sts = card.results.map((r) => R[r].status)
    el.chip.replaceChildren(card.results.length ? chip(worst(sts)) : '')
    el.results.replaceChildren(...card.results.map((r) => h('div', { class: 'result' }, chip(R[r].status), h('span', { class: 'what' }, h('span', { class: 'rname' }, LINKS[r][0]), R[r].detail))))
    el.inside.replaceChildren(...insideViews(card.id, D))
  }
  for (const [name, keyName] of [['userJwk', 'userJwk'], ['storeJwk', 'storeJwk'], ['jwks', 'jwks']]) {
    const span = $(`[data-prov="${name}"]`)
    if (!span) continue
    const t = PROVTEXT(S.src[keyName])
    span.textContent = t ? `· ${t[0]}` : ''
    span.className = `prov ${t?.[1] ?? ''}`
  }
  updateButtons(D)
  renderVerdict(R)
}

function renderVerdict(R) {
  const v = $('#verdict')
  const names = Object.keys(LINKS)
  const by = (st) => names.filter((n) => R[n].status === st)
  const failed = by('fail'), waiting = by('todo'), done = by('pass').length + by('warn').length
  const applicable = names.length - by('skip').length   // a link that is not needed here (no approval asked, no payment yet) is not counted
  const anyInput = names.some((n) => !['todo', 'skip'].includes(R[n].status))
  const list = h('ul', {}, names.map((n) => h('li', {}, h('a', { href: `#card-${LINKS[n][1]}` }, `${STATUS[R[n].status][0]} ${LINKS[n][0]}`))))
  let cls = '', title, note = null
  if (failed.length) { cls = 'fail'; title = '✘ Something does not add up'; note = `The failing link${failed.length > 1 ? 's are' : ' is'}: ${failed.map((n) => LINKS[n][0]).join('; ')}. A receipt that fails here should not be relied on.` }
  else if (!anyInput) { title = 'Nothing to check yet'; note = 'Load a bundle, or start with step 1 or 2.' }
  else if (waiting.length) { title = `${done} of ${applicable} links checked so far`; note = 'Nothing has failed. Each piece you add checks another link.' }
  else if (by('warn').length) { cls = 'warn'; title = '! The chain holds, with notes'; note = 'Every signature checked out, but some links could only be partly proven. Read the notes below.' }
  else { cls = 'pass'; title = '✔ Every link checks out'; note = 'The user’s mandate, the agent’s purchase, the store’s receipts, the sign-ins and the payment all agree.' }
  const fromBundle = ['userJwk', 'storeJwk', 'jwks'].some((k) => S.src[k] === 'bundle')
  v.className = `verdict ${cls}`
  v.replaceChildren(h('h3', {}, title), note ? h('p', { class: 'note' }, note) : null, list,
    !failed.length && done && fromBundle ? h('p', { class: 'note' }, 'One caution: the keys used here came from the bundle itself, so this proves the bundle is consistent, not that its keys are genuine. Fetch the store’s key (step 4) and Keycloak’s keys (step 6) from their own servers to make the check independent.') : null)
}

// ── the extra controls inside some cards ────────────────────────────────────────────────────────────────────
const note = (text, cls = '') => h('p', { class: `msg ${cls}`, role: 'status' }, text)
async function getJson(url, opts) {
  const u = new URL(url, document.baseURI)
  if (!(u.protocol === 'https:' || ['localhost', '127.0.0.1'].includes(u.hostname))) throw new Error('only https addresses (or localhost) can be fetched')
  try {
    // Cookies only go to this page's own server (a tunnel's browser-warning cookie lives there); never to anyone else.
    const r = await fetch(u, { credentials: u.origin === location.origin ? 'same-origin' : 'omit', redirect: 'follow', ...opts })
    if (!r.ok) throw new Error(`the server answered ${r.status}`)
    return await r.json()
  } catch (e) {
    throw new Error(/Failed to fetch|NetworkError|Load failed/i.test(e.message) ? `this browser could not read ${u.host}. It may be unreachable, or may not allow other sites to read it. You can open the address yourself and paste what it shows` : e.message)
  }
}
const busy = async (btn, msgEl, work) => {
  btn.disabled = true; msgEl.className = 'msg'; msgEl.textContent = 'Working…'
  try { const m = await work(); msgEl.className = 'msg ok'; msgEl.textContent = m ?? '' } catch (e) { msgEl.className = 'msg err'; msgEl.textContent = `Could not do that: ${e.message}.` }
  btn.disabled = false
}

const extras = {}   // card id → { node, update(D) }
function buildExtras() {
  // 1. order: paste the order JSON, or fetch it
  {
    const ta = h('textarea', { rows: 4, spellcheck: 'false', id: 'order-json', placeholder: '{ "orderId": "ord_…", "merchant": "luxe", "sku": "…", "receipts": { … } }' })
    const url = h('input', { type: 'text', id: 'order-url', placeholder: 'https://…/shop/luxe/orders/ord_…' })
    const msg = note('')
    const apply = (v) => {
      const r = v?.order ?? v
      const pick = (a, b) => (typeof a === 'string' ? a : typeof b === 'string' ? b : '')
      if (!r || typeof r !== 'object' || !(r.merchant || r.orderId || r.id)) throw new Error('that does not look like an order')
      Object.assign(S.order, { id: pick(r.orderId, r.id), merchant: pick(r.merchant), sku: pick(r.sku), item: pick(r.item), amount: pick(r.amount), currency: pick(r.currency) || 'OUSD', status: pick(r.status), createdAt: pick(r.createdAt), txHash: pick(r.txHash) })
      if (r.receipts?.mandate) S.mandateReceipt = r.receipts.mandate
      if (r.receipts?.payment) S.paymentReceipt = r.receipts.payment
      syncInputs(); schedule()
    }
    ta.addEventListener('input', () => { const j = jsonOf(ta.value); if (j.value) { try { apply(j.value); msg.className = 'msg ok'; msg.textContent = 'Filled in from the pasted order.' } catch (e) { msg.className = 'msg err'; msg.textContent = `${e.message}.` } } else if (j.error) { msg.className = 'msg'; msg.textContent = '' } })
    const fetchBtn = h('button', { type: 'button', class: 'btn ghost small' }, 'Fetch it')
    fetchBtn.addEventListener('click', () => busy(fetchBtn, msg, async () => { const v = await getJson(url.value.trim()); apply(v); return 'Fetched and filled in.' }))
    extras.order = { node: h('div', { class: 'fields' },
      h('label', { class: 'lbl', for: 'order-json' }, 'Paste the receipt’s raw data'), ta,
      h('label', { class: 'lbl', for: 'order-url' }, '…or fetch it from its address'), h('div', { class: 'row' }, url, fetchBtn), msg,
      h('p', { class: 'help' }, 'Or fill the fields in yourself:')) }
  }
  // 3. closed: which key verifies it
  {
    const p = h('p', { class: 'help' })
    extras.closed = { node: p, update: (D) => { p.textContent = D.agentKid ? `Verified with the agent key named in the open mandate (fingerprint ${short(D.agentKid, 16)}).` : 'The agent’s key comes from the open mandate in step 2.' } }
  }
  // 4. receipts: fetch the store's own key
  {
    const msg = note(''), btn = h('button', { type: 'button', class: 'btn ghost small' }, 'Get the store’s key from the store')
    let issuer = ''
    btn.addEventListener('click', () => busy(btn, msg, async () => {
      const j = await getJson(`${issuer.replace(/\/$/, '')}/catalog.json`)
      const k = j?.merchant?.receiptKey ?? j?.receiptKey   // the catalog lists it under "merchant"
      if (!(k?.kty === 'OKP' && k?.crv === 'Ed25519' && k.x)) throw new Error('the store’s catalog has no receipt key')
      S.storeJwk = JSON.stringify(k, null, 2); S.src.storeJwk = `host:${hostOf(issuer)}`; syncInputs(); schedule()
      return `Fetched from ${hostOf(issuer)}. The receipts are now checked against the key the store publishes itself.`
    }))
    extras.receipts = { node: h('div', {}, h('div', { class: 'row' }, btn), msg), update: (D) => {
      issuer = D.mr?.payload?.iss ?? D.pr?.payload?.iss ?? ''
      btn.disabled = !issuer
      btn.textContent = issuer ? `Get the store’s key from ${hostOf(issuer)}` : 'Get the store’s key from the store (needs a receipt first)'
    } }
  }
  // 6. proofs: fetch Keycloak's keys
  {
    const msg = note(''), btn = h('button', { type: 'button', class: 'btn ghost small' }, 'Get Keycloak’s keys from Keycloak')
    let issuer = ''
    btn.addEventListener('click', () => busy(btn, msg, async () => {
      const j = await getJson(`${issuer.replace(/\/$/, '')}/protocol/openid-connect/certs`)
      if (!Array.isArray(j?.keys)) throw new Error('that address did not return a key set')
      S.oidc.jwks = JSON.stringify(j, null, 2); S.src.jwks = `host:${hostOf(issuer)}`
      if (!S.oidc.issuer.trim()) S.oidc.issuer = issuer
      syncInputs(); schedule()
      return `Fetched from ${hostOf(issuer)}. The sign-ins are now checked against the keys Keycloak publishes itself.`
    }))
    extras.proofs = { node: h('div', {}, h('div', { class: 'row' }, btn), msg), update: (D) => {
      issuer = S.oidc.issuer.trim() || D.grant?.claims?.iss || ''
      btn.disabled = !issuer
      btn.textContent = issuer ? `Get Keycloak’s keys from ${hostOf(issuer)}` : 'Get Keycloak’s keys (needs the issuer or a token first)'
    } }
  }
  // 7. chain: look the transaction up
  {
    const msg = note(''), btn = h('button', { type: 'button', class: 'btn ghost small' }, 'Look up on the network')
    btn.addEventListener('click', () => busy(btn, msg, async () => {
      const r = await getJson(S.chain.rpc.trim(), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [S.order.txHash.trim()] }) })
      S.chain.receiptJson = JSON.stringify(r.result ?? r, null, 2); syncInputs(); schedule()
      return r.result ? 'Fetched the transaction receipt.' : 'The network has no such transaction.'
    }))
    extras.chain = { node: h('div', {}, h('div', { class: 'row' }, btn), msg), update: () => { btn.disabled = !(S.chain.rpc.trim() && S.order.txHash.trim()) } }
  }
}
function updateButtons(D) { for (const e of Object.values(extras)) e.update?.(D) }

// ── building the page ───────────────────────────────────────────────────────────────────────────────────────
function fieldNode(f) {
  const id = `f-${f.key.replace('.', '-')}`
  const el = f.kind === 'area' ? h('textarea', { id, rows: f.rows ?? 3, spellcheck: 'false', placeholder: f.ph ?? '' })
    : f.kind === 'select' ? h('select', { id }, f.opts.map(([v, t]) => h('option', { value: v }, t)))
    : h('input', { id, type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: f.ph ?? '' })
  el.addEventListener('input', () => { setp(f.key, el.value); if (PROV[f.key]) S.src[PROV[f.key]] = 'you'; schedule() })
  fieldEls.push({ el, key: f.key })
  return h('div', {}, h('label', { class: 'lbl', for: id }, f.label, f.prov ? h('span', { class: 'prov', 'data-prov': f.prov }) : null), el, f.help ? h('p', { class: 'help' }, f.help) : null)
}
function syncInputs() { for (const { el, key } of fieldEls) el.value = getp(key) ?? '' }

function buildCards() {
  const ol = $('#cards')
  CARDS.forEach((card, i) => {
    const cip = h('span', { class: 'cardchip' }), results = h('div', { class: 'results' }), insideBox = h('div', {})
    const x = extras[card.custom]
    const next = i < CARDS.length - 1 ? h('div', { class: 'nextrow' }, h('button', { type: 'button', class: 'btn ghost small', onclick: () => { const n = $(`#card-${CARDS[i + 1].id}`); n.scrollIntoView({ behavior: 'smooth', block: 'start' }); $('textarea, input, select', n)?.focus({ preventScroll: true }) } }, `Next: ${CARDS[i + 1].title} →`)) : null
    const li = h('li', { class: 'card', id: `card-${card.id}` },
      h('header', {}, h('span', { class: 'num', 'aria-hidden': 'true' }, String(i + 1)), h('div', {}, h('h3', {}, card.title), h('p', { class: 'q' }, card.q)), cip),
      h('div', { class: 'body' },
        h('p', { class: 'proves' }, card.proves), h('p', { class: 'where' }, h('strong', {}, 'Where to find it. '), card.where),
        card.custom === 'order' ? x.node : null,
        h('div', { class: 'fields' }, card.fields.map((row) => (row.length > 1 ? h('div', { class: 'pair' }, row.map(fieldNode)) : fieldNode(row[0])))),
        card.custom && card.custom !== 'order' ? x.node : null,
        results, insideBox, next))
    ol.append(li)
    cardEls[card.id] = { chip: cip, results, inside: insideBox }
  })
}

// ── loading, modes, tampering ───────────────────────────────────────────────────────────────────────────────
let timer = 0, runId = 0
function schedule() { clearTimeout(timer); timer = setTimeout(run, 120) }
async function run() {
  const id = ++runId
  const out = await compute()
  if (id === runId) render(out)
}

function fillFromBundle(b, example) {
  const keep = mode
  S = blank()
  const o = b.order ?? {}
  Object.assign(S.order, { merchant: o.merchant ?? '', sku: o.sku ?? '', item: o.item ?? '', amount: o.amount ?? '', currency: o.currency ?? 'OUSD', id: o.id ?? '', status: o.status ?? '', createdAt: o.createdAt ?? '', txHash: o.txHash ?? '' })
  S.open = b.mandates?.open ?? ''; S.closed = b.mandates?.closed ?? ''
  S.userJwk = b.keys?.user?.jwk ? JSON.stringify(b.keys.user.jwk, null, 2) : ''; S.userSub = b.keys?.user?.sub ?? ''
  S.mandateReceipt = b.receipts?.mandate ?? ''; S.paymentReceipt = b.receipts?.payment ?? ''
  S.storeJwk = b.keys?.store?.jwk ? JSON.stringify(b.keys.store.jwk, null, 2) : ''
  Object.assign(S.req, { authority: b.request?.authority ?? '', path: b.request?.path ?? '', sigInput: b.request?.headers?.['signature-input'] ?? '', signature: b.request?.headers?.signature ?? '' })
  Object.assign(S.oidc, { issuer: b.keys?.oidc?.issuer ?? '', audience: b.keys?.oidc?.audience ?? '', jwks: b.keys?.oidc?.jwks ? JSON.stringify(b.keys.oidc.jwks, null, 2) : '' })
  S.grantToken = b.grant?.proof?.idToken ?? ''; S.grantDev = b.grant?.proof?.mode === 'dev-unproven'
  Object.assign(S.approval, { id: b.approval?.id ?? '', decidedAt: b.approval?.decidedAt ?? '', token: b.approval?.proof?.idToken ?? '' })
  Object.assign(S.chain, { rpc: b.chain?.rpc ?? '', token: b.chain?.token ?? '', payer: b.chain?.payer ?? '', payee: b.chain?.payee ?? '', receiptJson: example && b._example?.chainReceipt ? JSON.stringify(b._example.chainReceipt, null, 2) : '' })
  S.agent = b.keys?.agent?.jwk ? { id: b.keys.agent.id, kid: b.keys.agent.kid, jwk: b.keys.agent.jwk } : null
  S.src = { userJwk: S.userJwk ? 'bundle' : '', storeJwk: S.storeJwk ? 'bundle' : '', jwks: S.oidc.jwks ? 'bundle' : '' }
  S.example = Boolean(example)
  original = structuredClone(S)
  mode = keep
}

function showSteps() { $('#steps').hidden = false }
function setMode(m) {
  mode = m
  for (const b of document.querySelectorAll('.choice')) b.setAttribute('aria-checked', String(b.dataset.mode === m))
  $('#bundle-box').hidden = m !== 'bundle'
  $('#pieces-box').hidden = m !== 'pieces'
  if (m === 'pieces') { showSteps(); schedule() }
}

function loadBundle(text, { example = false, where = '#bundle-msg' } = {}) {
  const msg = $(where)
  let b
  try { b = typeof text === 'string' ? JSON.parse(text) : text } catch { msg.className = 'msg err'; msg.textContent = 'That is not valid JSON. Paste the whole file, from the first { to the last }.'; return false }
  if (b?.version !== V.EVIDENCE_VERSION || !b?.order) { msg.className = 'msg err'; msg.textContent = `That does not look like an Agent Pay evidence bundle (it should say "version": "${V.EVIDENCE_VERSION}" and have an "order").`; return false }
  fillFromBundle(b, example)
  syncInputs(); showSteps(); $('#tamper').hidden = false
  msg.className = 'msg ok'; msg.textContent = example ? 'Loaded the example. Every field below is filled in so you can see what each piece looks like.' : `Loaded ${b.order.id ?? 'the bundle'}. Every field below is filled in from it.`
  run().then(() => $('#verdict').scrollIntoView({ behavior: 'smooth', block: 'start' }))
  return true
}
async function loadExample(where) {
  const msg = $(where)
  try {
    const r = await fetch(new URL('example-bundle.json', document.baseURI))
    if (!r.ok) throw new Error(`status ${r.status}`)
    loadBundle(await r.json(), { example: true, where })
  } catch (e) { msg.className = 'msg err'; msg.textContent = `Could not load the example: ${e.message}.` }
}

async function tamper(kind) {
  if (!original) return
  if (kind === 'reset') { S = structuredClone(original) }
  else if (kind === 'price') S.order.amount = '1'
  else if (kind === 'flip') { const t = S.open; const i = t.lastIndexOf('.') + 3; S.open = t.slice(0, i) + (t[i] === 'A' ? 'B' : 'A') + t.slice(i + 1) }
  else if (kind === 'key') {
    const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
    S.userJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.publicKey), null, 2); S.src.userJwk = 'button'
  }
  syncInputs(); schedule()
}

function wire() {
  for (const b of document.querySelectorAll('.choice')) b.addEventListener('click', () => setMode(b.dataset.mode))
  $('#load-paste').addEventListener('click', () => loadBundle($('#paste').value))
  $('#load-example').addEventListener('click', () => loadExample('#bundle-msg'))
  $('#load-example-2').addEventListener('click', () => loadExample('#pieces-msg'))
  const readFile = (f) => { if (!f) return; if (f.size > 2_000_000) { $('#bundle-msg').className = 'msg err'; $('#bundle-msg').textContent = 'That file is too large for an evidence bundle.'; return } f.text().then((t) => loadBundle(t)) }
  $('#file').addEventListener('change', (e) => readFile(e.target.files[0]))
  const drop = $('#drop')
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over') })
  drop.addEventListener('dragleave', () => drop.classList.remove('over'))
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); readFile(e.dataTransfer.files[0]) })
  for (const b of document.querySelectorAll('[data-tamper]')) b.addEventListener('click', () => tamper(b.dataset.tamper))
}

buildExtras()
buildCards()
wire()
run()
