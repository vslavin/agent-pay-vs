import { readFileSync } from 'node:fs'
import { visa } from './visa.mjs'

// Prints a merchant's record from Visa's sandbox registry (read-only).
//   node show-merchant.mjs <merchant id | username>
// A username is looked up in the local wallet service to find its Visa merchant ID.

const arg = process.argv[2]
if (!arg) { console.error('usage: node show-merchant.mjs <merchant id | username>'); process.exit(1) }

let id = arg
if (!/^[0-9a-f-]{36}$/i.test(arg)) {
  const token = readFileSync(new URL('../wallet-service/data/service-token', import.meta.url), 'utf8').trim()
  const { wallets } = await (await fetch('http://127.0.0.1:3100/wallets', { headers: { 'x-wallet-token': token } })).json()
  id = wallets.find((w) => w.username === arg)?.visa?.merchantId
  if (!id) { console.error(`No Visa merchant ID saved for "${arg}".`); process.exit(1) }
}

const r = await visa('GET', `/vmrs/v1/merchants/${id}`)
console.log(`GET /vmrs/v1/merchants/${id} -> HTTP ${r.status}`)
if (r.json) console.log(JSON.stringify(r.json, null, 2))
