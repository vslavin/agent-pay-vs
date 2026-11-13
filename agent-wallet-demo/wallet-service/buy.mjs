import { readFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { verifyJws, MANDATE_RECEIPT_TYP, PAYMENT_RECEIPT_TYP } from './mandate.mjs'

// Acts as your agent: buys one item from a store using a mandate you granted in the app.
//   node buy.mjs --store https://<domain>/shop/<store> --agent agt_xxxxxxxxxxxx --mandate mnd_xxxxxxxxxxxx --item 3 [--pay]
// --item is a number from the store's catalog (1 = first product) or a SKU. Without --pay it stops at the price quote.
// At a human-present store it prints the approval link, then waits (up to 5 minutes) for you to approve in the app.
// It talks to the wallet service on this machine, the way an agent runtime with a wallet would.

const { values: o } = parseArgs({ options: {
  store: { type: 'string' }, agent: { type: 'string' }, mandate: { type: 'string' }, item: { type: 'string' },
  pay: { type: 'boolean', default: false }, service: { type: 'string', default: 'http://127.0.0.1:3100' }, 'token-file': { type: 'string' },
} })
if (!o.store || !o.agent || !o.mandate || !o.item) { console.error('usage: node buy.mjs --store <store url> --agent <agt_id> --mandate <mnd_id> --item <number or sku> [--pay] [--service <url>]'); process.exit(2) }

const token = readFileSync(o['token-file'] ?? `${process.env.WALLET_DATA_DIR ?? new URL('./data', import.meta.url).pathname}/service-token`, 'utf8').trim()
const svc = async (method, path, body) => {
  const r = await fetch(o.service + path, { method, headers: { 'x-wallet-token': token, 'content-type': 'application/json' }, body: body && JSON.stringify(body) })
  return { status: r.status, json: await r.json().catch(() => null) }
}
const say = (s) => console.log(s)
const die = (s) => { console.error(`\n✘ ${s}`); process.exit(1) }

const store = new URL(o.store)
const username = store.pathname.split('/').filter(Boolean)[1]
const catalog = await (await fetch(`${store.origin}/shop/${username}/catalog.json`, { headers: { 'ngrok-skip-browser-warning': '1' } })).json()
const product = /^\d+$/.test(o.item) ? catalog.products[Number(o.item) - 1] : catalog.products.find((p) => p.sku === o.item)
if (!product) die(`No such item ${o.item}. The store has ${catalog.products.length} products.`)
const mandates = await svc('GET', `/agents/${o.agent}/mandates`)
const mandate = mandates.json?.mandates?.find((m) => m.id === o.mandate)
if (!mandate) die(`Agent ${o.agent} has no mandate ${o.mandate}.`)
say(`Agent ${o.agent} wants: ${product.name} (${product.sku}) for ${product.price} OUSD from ${catalog.merchant.name}`)
say(`Mandate ${mandate.id}: ${mandate.status}, up to ${mandate.maxPerPurchase} per purchase, ${mandate.remaining} of ${mandate.budget} left\n`)
if (mandate.status !== 'active') die(`That mandate is ${mandate.status}.`)

const order = { amount: product.price, currency: 'OUSD', merchant: username, quantity: 1, sku: product.sku }
async function checkout() {
  const headers = (await svc('POST', '/agents/sign', { agentId: o.agent, authority: store.host, path: `/shop/${username}/checkout`, tag: 'agent-payer-auth' })).json.headers
  const closed = (await svc('POST', `/agents/${o.agent}/closed-mandate`, { openJws: mandate.jws, order, payee: catalog.payment.payTo })).json?.jws
  const res = await fetch(`${store.origin}/shop/${username}/checkout`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'ngrok-skip-browser-warning': '1', ...headers },
    body: JSON.stringify({ sku: product.sku, mandates: { open: mandate.jws, closed } }),
  })
  return { http: res.status, body: await res.json().catch(() => ({})) }
}

let r = await checkout()
if (r.body.approval && r.body.status === 'approval_required') {
  say(`⏸  This store needs you to approve this exact purchase.\n   Open: ${r.body.approval.url}\n   (waiting up to 5 minutes; approve with your passkey in the app)\n`)
  const until = Date.now() + 5 * 60_000
  while (Date.now() < until) {
    await new Promise((res) => setTimeout(res, 4000))
    r = await checkout()
    if (r.http === 402) break
    if (/declined/.test(r.body.reason ?? '')) die('You declined the purchase.')
    process.stdout.write('.')
  }
  say('')
}
if (r.http !== 402) die(`Checkout refused (HTTP ${r.http}, ${r.body.code}): ${r.body.reason ?? ''}`)
const q = r.body
say(`✔ Store verified the agent and the mandate. Quote: pay ${q.payment.amount} ${q.payment.currency} to ${q.payment.payTo.slice(0, 10)}…  order ${q.orderId}`)
const key = catalog.merchant.receiptKey
const mr = verifyJws(q.receipts?.mandate ?? '', key, MANDATE_RECEIPT_TYP)
say(`  mandate receipt: ${mr.ok ? `signed by the store, result ${mr.payload.result}` : 'DID NOT VERIFY'}`)
if (!o.pay) { say('\nNot paying (no --pay). The quote expires in 5 minutes.'); process.exit(0) }

say('\nPaying from your wallet…')
const paid = await svc('POST', `/agents/${o.agent}/pay`, { orderId: q.orderId })
if (paid.status !== 200) die(`Payment failed: ${paid.json?.error ?? paid.status}`)
const final = await (await fetch(`${store.origin}/shop/${username}/orders/${q.orderId}`, { headers: { 'ngrok-skip-browser-warning': '1' } })).json()
const pr = verifyJws(final.receipts?.payment ?? '', key, PAYMENT_RECEIPT_TYP)
say(`✔ Paid on-chain: https://explore.testnet.tempo.xyz/tx/${paid.json.txHash}`)
say(`  order status: ${final.status}`)
say(`  payment receipt: ${pr.ok ? `signed by the store, ${pr.payload.status}, payment_id ${pr.payload.payment_id}` : 'DID NOT VERIFY'}`)
process.exit(pr.ok && final.status === 'paid' ? 0 : 1)
