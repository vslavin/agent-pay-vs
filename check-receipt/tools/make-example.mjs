// Builds example-bundle.json: a synthetic but complete evidence bundle (a human-present purchase with a per-purchase
// approval) for the page's "Try an example" button. Everything is signed with throwaway keys, including a throwaway
// stand-in for Keycloak, so the example never contains anything real. Needs the sibling wallet-service folder, because
// it signs with that code on purpose: the page must verify what the real service would produce.
//   node tools/make-example.mjs
import { writeFileSync } from 'node:fs'
import { generateKeyPairSync, createSign } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { generateAgentKey, signRequest } from '../../agent-wallet-demo/wallet-service/tap.mjs'
import { generateUserKey, createOpenMandate, createClosedMandate, createMandateReceipt, createPaymentReceipt, orderOf, orderHash, sha256b64u, toMicro } from '../../agent-wallet-demo/wallet-service/mandate.mjs'
import { mandateTerms, approvalTerms, termsHash, EVIDENCE_VERSION } from '../../agent-wallet-demo/wallet-service/evidence.mjs'
import { memoTopic, MEMO_TOPIC } from '../../agent-wallet-demo/wallet-service/payment.mjs'

const NOW = Date.UTC(2026, 10, 14, 18, 0, 0)
const sec = Math.floor(NOW / 1000)
const HOST = 'agent-pay.example'
const ISSUER = 'https://login.agent-pay.example/realms/demo', AUD = 'demo-app'
const PAYER = '0x1111111111111111111111111111111111111111', PAYEE = '0x2222222222222222222222222222222222222222', TOKEN = '0x20c0000000000000000000006a37da5c996874be'
const pad = (a) => '0x' + a.slice(2).padStart(64, '0')

const kc = generateKeyPairSync('rsa', { modulusLength: 2048 })
const kcJwk = { ...kc.publicKey.export({ format: 'jwk' }), kid: 'example-key-1', use: 'sig', alg: 'RS256' }
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
const idToken = (claims) => {
  const h = b64u({ alg: 'RS256', typ: 'JWT', kid: kcJwk.kid }), p = b64u({ iss: ISSUER, aud: AUD, iat: sec - 5, exp: sec + 300, amr: ['webauthn'], ...claims })
  return `${h}.${p}.${createSign('RSA-SHA256').update(`${h}.${p}`).sign(kc.privateKey).toString('base64url')}`
}

const user = generateUserKey(), agent = generateAgentKey(), store = generateUserKey()
const sub = 'a1b2c3d4-0000-4000-8000-example00001'
const open = createOpenMandate({ user, userSub: sub, agent: { id: 'agt_9f3c2a71d4e5', publicJwk: agent.publicJwk },
  constraints: { merchants: ['luxe'], merchantNames: { luxe: 'Luxe' }, maxPerPurchase: '500', budget: '1000', currency: 'OUSD' }, ttlSeconds: 24 * 3600, now: NOW - 3600_000, id: 'mnd_5e1a77c0b9d2' })
const order = { id: 'ord_7c41e0a9b3d5', merchant: 'luxe', sku: 'LUX-001', item: 'Meridian 38', amount: '420', currency: 'OUSD', status: 'paid', createdAt: new Date(NOW).toISOString(), paidAt: new Date(NOW + 20_000).toISOString(), txHash: '0x' + '5c'.repeat(32) }
const want = orderOf({ merchant: order.merchant, sku: order.sku, amount: order.amount })
const closed = createClosedMandate({ agentKey: agent, openJws: open.jws, order: want, payee: PAYEE, now: NOW })
const headers = Object.fromEntries(Object.entries(signRequest({ privateJwk: agent.privateJwk, keyid: agent.keyid, authority: HOST, path: '/shop/luxe/checkout', tag: 'agent-payer-auth', now: NOW })).map(([k, v]) => [k.toLowerCase(), v]))
const closedHash = sha256b64u(closed.jws)
const issuer = `https://${HOST}/shop/luxe`
const grantTerms = mandateTerms({ sub, agentId: 'agt_9f3c2a71d4e5', merchants: ['luxe'], maxPerPurchase: '500', budget: '1000', hours: 24 })
const approvalId = 'apr_3d8b0c6e1f47', decided = sec + 8

const bundle = {
  version: EVIDENCE_VERSION, generatedAt: new Date(NOW + 60_000).toISOString(),
  _example: {
    note: 'Synthetic example. Every key here was generated for this file; the "Keycloak" that signed the sign-in proofs is a throwaway stand-in. The transaction does not exist on any network.',
    chainReceipt: { status: 'success', logs: [{ address: TOKEN, topics: [MEMO_TOPIC, pad(PAYER), pad(PAYEE), memoTopic(order.id)], data: '0x' + toMicro(order.amount).toString(16).padStart(64, '0') }] },
  },
  order: { ...order, quantity: 1 },
  mandates: { open: open.jws, closed: closed.jws },
  request: { authority: HOST, path: '/shop/luxe/checkout', headers },
  receipts: {
    mandate: createMandateReceipt({ issuer, key: store, reference: closedHash, now: NOW }).jws,
    payment: createPaymentReceipt({ issuer, key: store, reference: closedHash, paymentId: order.id, txHash: order.txHash, now: NOW + 20_000 }).jws,
  },
  grant: { proof: { idToken: idToken({ sub, auth_time: sec - 3600 - 30, nonce: termsHash(grantTerms) }) } },
  approval: { id: approvalId, createdAt: new Date(NOW - 20_000).toISOString(), decidedAt: new Date(decided * 1000).toISOString(),
    proof: { idToken: idToken({ sub, auth_time: decided - 12, nonce: termsHash(approvalTerms({ approvalId, orderHash: orderHash(want), mandateId: open.id })) }) } },
  chain: { network: 'Example network', chainId: 0, rpc: 'https://rpc.example.invalid', token: TOKEN, payer: PAYER, payee: PAYEE, txHash: order.txHash, blockNumber: null },
  keys: {
    user: { sub, jwk: user.publicJwk }, agent: { id: 'agt_9f3c2a71d4e5', kid: agent.keyid, jwk: agent.publicJwk },
    store: { username: 'luxe', kid: store.kid, jwk: store.publicJwk }, oidc: { issuer: ISSUER, audience: AUD, jwks: { keys: [kcJwk] } },
  },
}
const out = fileURLToPath(new URL('../example-bundle.json', import.meta.url))
writeFileSync(out, JSON.stringify(bundle, null, 2) + '\n')
console.log('wrote', out)
