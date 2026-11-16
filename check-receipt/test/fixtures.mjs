// Honest bundles built with the wallet service's own code, so the tests check the page's verifier against the real thing.
import { generateKeyPairSync, createSign } from 'node:crypto'
import { generateAgentKey, signRequest } from '../../agent-wallet-demo/wallet-service/tap.mjs'
import { generateUserKey, createOpenMandate, createClosedMandate, createMandateReceipt, createPaymentReceipt, orderOf, orderHash, sha256b64u, toMicro } from '../../agent-wallet-demo/wallet-service/mandate.mjs'
import { mandateTerms, approvalTerms, termsHash, EVIDENCE_VERSION } from '../../agent-wallet-demo/wallet-service/evidence.mjs'
import { memoTopic, MEMO_TOPIC } from '../../agent-wallet-demo/wallet-service/payment.mjs'

export const NOW = Date.UTC(2026, 10, 14, 18, 0, 0)
export const ISS = 'https://id.example/realms/demo', AUD = 'demo-app'
export const PAYER = '0x1111111111111111111111111111111111111111', PAYEE = '0x2222222222222222222222222222222222222222', TOKEN = '0x20c0000000000000000000006a37da5c996874be'
export const pad = (a) => '0x' + a.slice(2).padStart(64, '0')
const sec = Math.floor(NOW / 1000)
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')

export function makeKeycloak(kid = 'kc1') {
  const kc = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...kc.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }
  const idToken = (claims) => {
    const h = b64u({ alg: 'RS256', typ: 'JWT', kid }), p = b64u({ iss: ISS, aud: AUD, iat: sec, exp: sec + 300, ...claims })
    return `${h}.${p}.${createSign('RSA-SHA256').update(`${h}.${p}`).sign(kc.privateKey).toString('base64url')}`
  }
  return { jwk, idToken }
}

export function build({ human = false, amount = '420', max = '500', budget = '1000', hours = 24 } = {}) {
  const user = generateUserKey(), agent = generateAgentKey(), store = generateUserKey(), kc = makeKeycloak()
  const open = createOpenMandate({ user, userSub: 'user-1', agent: { id: 'agt_1', publicJwk: agent.publicJwk }, constraints: { merchants: ['luxe'], merchantNames: { luxe: 'Luxe' }, maxPerPurchase: max, budget, currency: 'OUSD' }, ttlSeconds: hours * 3600, now: NOW - 60_000 })
  const order = { id: 'ord_0123456789ab', merchant: 'luxe', sku: 'LUX-001', item: 'Meridian 38', amount, currency: 'OUSD', status: 'paid', createdAt: new Date(NOW).toISOString(), txHash: '0x' + 'ab'.repeat(32) }
  const want = orderOf({ merchant: 'luxe', sku: 'LUX-001', amount })
  const closed = createClosedMandate({ agentKey: agent, openJws: open.jws, order: want, payee: PAYEE, now: NOW })
  const headers = Object.fromEntries(Object.entries(signRequest({ privateJwk: agent.privateJwk, keyid: agent.keyid, authority: 'shop.example', path: '/shop/luxe/checkout', tag: 'agent-payer-auth', now: NOW })).map(([k, v]) => [k.toLowerCase(), v]))
  const closedHash = sha256b64u(closed.jws)
  const grantTerms = mandateTerms({ sub: 'user-1', agentId: 'agt_1', merchants: ['luxe'], maxPerPurchase: max, budget, hours })
  const bundle = {
    version: EVIDENCE_VERSION, order, mandates: { open: open.jws, closed: closed.jws },
    request: { authority: 'shop.example', path: '/shop/luxe/checkout', headers },
    receipts: {
      mandate: createMandateReceipt({ issuer: 'https://shop.example/shop/luxe', key: store, reference: closedHash, now: NOW }).jws,
      payment: createPaymentReceipt({ issuer: 'https://shop.example/shop/luxe', key: store, reference: closedHash, paymentId: order.id, txHash: order.txHash, now: NOW }).jws,
    },
    grant: { proof: { idToken: kc.idToken({ sub: 'user-1', auth_time: sec - 60 - 20, nonce: termsHash(grantTerms) }) } },
    approval: null, chain: { token: TOKEN, payer: PAYER, payee: PAYEE, txHash: order.txHash },
    keys: { user: { sub: 'user-1', jwk: user.publicJwk }, agent: { id: 'agt_1', kid: agent.keyid, jwk: agent.publicJwk }, store: { username: 'luxe', kid: store.kid, jwk: store.publicJwk }, oidc: { issuer: ISS, audience: AUD, jwks: { keys: [kc.jwk] } } },
  }
  if (human) {
    const approvalId = 'apr_0123456789ab', decided = sec + 5
    bundle.approval = { id: approvalId, createdAt: new Date(NOW - 30_000).toISOString(), decidedAt: new Date(decided * 1000).toISOString(),
      proof: { idToken: kc.idToken({ sub: 'user-1', auth_time: decided - 10, nonce: termsHash(approvalTerms({ approvalId, orderHash: orderHash(want), mandateId: open.id })) }) } }
  }
  return { bundle, user, agent, store, kc, open, closed, want }
}

export const goodChain = (orderId = 'ord_0123456789ab', amount = '420') => ({ status: 'success', logs: [{ address: TOKEN, topics: [MEMO_TOPIC, pad(PAYER), pad(PAYEE), memoTopic(orderId)], data: '0x' + toMicro(amount).toString(16).padStart(64, '0') }] })
