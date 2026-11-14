import { readFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { verifyEvidence } from './evidence.mjs'

// Checks an Agent Pay evidence bundle without trusting whoever produced it.
//   node verify-evidence.mjs bundle.json [--chain] [--kc-jwks <url or file>]
// --chain     look the transaction up on the network and check payer, payee, amount and memo
// --kc-jwks   use Keycloak's published key set (fetch it yourself from the realm's /protocol/openid-connect/certs)
//             instead of the copy inside the bundle, so the sign-in proofs do not rely on the bundle's own keys

const { values: o, positionals } = parseArgs({ allowPositionals: true, options: { chain: { type: 'boolean', default: false }, 'kc-jwks': { type: 'string' } } })
if (!positionals[0]) { console.error('usage: node verify-evidence.mjs <bundle.json> [--chain] [--kc-jwks <url or file>]'); process.exit(2) }
const bundle = JSON.parse(readFileSync(positionals[0], 'utf8'))

const opts = {}
if (o['kc-jwks']) {
  const src = o['kc-jwks']
  opts.oidcJwks = /^https?:/.test(src) ? await (await fetch(src)).json() : JSON.parse(readFileSync(src, 'utf8'))
}
if (o.chain) {
  const r = await (await fetch(bundle.chain.rpc, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [bundle.chain.txHash] }) })).json()
  opts.chainReceipt = r.result ? { status: r.result.status === '0x1' ? 'success' : 'reverted', logs: r.result.logs } : { status: 'not found', logs: [] }
}

const result = verifyEvidence(bundle, opts)
const icon = { pass: '✔', fail: '✘', warn: '!', skip: '–' }
console.log(`Evidence for ${bundle.order?.id ?? '(unknown order)'}\n`)
for (const s of result.steps) console.log(` ${icon[s.status]} ${s.name.padEnd(20)} ${s.detail}`)
console.log()
if (!result.ok) console.log('RESULT: the evidence does NOT hold together. See the failed steps above.')
else if (!result.proven) console.log('RESULT: the signed chain holds together, but some steps were skipped or could not be proven (marked ! or –).')
else console.log('RESULT: every step checked out.')
if (!o['kc-jwks']) console.log('Note: the Keycloak keys used for the sign-in proofs came from the bundle itself. Pass --kc-jwks to check them against the realm\'s published keys.')
process.exit(result.ok ? 0 : 1)
