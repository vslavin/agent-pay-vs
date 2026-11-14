import http from 'node:http'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs'
import { createPublicClient, createWalletClient, http as rpcHttp, defineChain, formatUnits, parseUnits, getAddress, toHex, stringToHex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { generateAgentKey, signRequest, TAGS } from './tap.mjs'
import { registerMerchantWithVisa, VisaRegistrationError, sandboxVmid, summarizeVisaMerchant, detail as visaDetail } from './visa-merchant.mjs'
import { generateUserKey, createOpenMandate, createClosedMandate, evaluateCheckout, decodeJws, verifyJws, toMicro, fromMicro, createMandateReceipt, createPaymentReceipt, mandateErrorCode, MANDATE_RECEIPT_TYP, PAYMENT_RECEIPT_TYP } from './mandate.mjs'
import { MEMO_TOPIC, MAX_MEMO_BYTES, findPayment } from './payment.mjs'
import { verifyIdToken } from './oidc.mjs'
import { mandateTerms, approvalTerms, termsHash, AUTH_FRESH_SECONDS, EVIDENCE_VERSION } from './evidence.mjs'
import { thumbprint } from './tap.mjs'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const PORT = Number(process.env.WALLET_SERVICE_PORT || 3100)
const RPC = 'https://rpc.moderato.tempo.xyz'
const OUSD = '0x20c0000000000000000000006a37da5c996874be'
const DECIMALS = 6
const GIFT_AMOUNT = '100'

const DATA_DIR = process.env.WALLET_DATA_DIR ? pathToFileURL(resolve(process.env.WALLET_DATA_DIR) + '/') : new URL('./data/', import.meta.url)
const dataFile = (name) => new URL(name, DATA_DIR)
const readJson = (name, fallback) => (existsSync(dataFile(name)) ? JSON.parse(readFileSync(dataFile(name), 'utf8')) : fallback)
function writeJson(name, value) {
  const tmp = dataFile(`${name}.tmp`)
  writeFileSync(tmp, JSON.stringify(value, null, 2))
  chmodSync(tmp, 0o600)
  renameSync(tmp, dataFile(name))
}

if (!existsSync(dataFile('service-token'))) {
  writeFileSync(dataFile('service-token'), randomBytes(32).toString('hex'))
  chmodSync(dataFile('service-token'), 0o600)
}
const TOKEN = Buffer.from(readFileSync(dataFile('service-token'), 'utf8').trim())

if (!existsSync(dataFile('treasury.json'))) {
  console.error('data/treasury.json missing: copy a funded testnet key there as {"privateKey": "0x..."}')
  process.exit(1)
}
const treasury = privateKeyToAccount(readJson('treasury.json').privateKey)
const wallets = readJson('wallets.json', {})
const agentKeys = readJson('agent-keys.json', {})

const publicEntry = (k) => ({ ...k.publicJwk, kid: k.keyid, use: 'sig', alg: 'EdDSA', agent: k.name, created: k.created })

function ensureAgentIdentity(agentId, name) {
  let k = agentKeys[agentId]
  if (!k) {
    const g = generateAgentKey()
    k = agentKeys[agentId] = { keyid: g.keyid, publicJwk: g.publicJwk, privateJwk: g.privateJwk, name, created: new Date().toISOString() }
    writeJson('agent-keys.json', agentKeys)
  }
  return publicEntry(k)
}

const chain = defineChain({
  id: 42431,
  name: 'Tempo Testnet (Moderato)',
  nativeCurrency: { name: 'n/a', symbol: 'n/a', decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
})
const pub = createPublicClient({ chain, transport: rpcHttp(RPC) })
const treasuryClient = createWalletClient({ account: treasury, chain, transport: rpcHttp(RPC) })
const abi = [
  { name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] },
  { name: 'transfer', type: 'function', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'uint256' }], outputs: [{ type: 'bool' }] },
  { name: 'transferWithMemo', type: 'function', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'uint256' }, { type: 'bytes32' }], outputs: [] },
]
const balanceOf = async (address) =>
  formatUnits(await pub.readContract({ address: OUSD, abi, functionName: 'balanceOf', args: [address] }), DECIMALS)

let queue = Promise.resolve()
const enqueue = (fn) => (queue = queue.then(fn, fn))

async function sendGift(sub) {
  const w = wallets[sub]
  try {
    const hash = await treasuryClient.writeContract({
      address: OUSD, abi, functionName: 'transfer', args: [w.address, parseUnits(GIFT_AMOUNT, DECIMALS)],
    })
    w.gift = { status: 'pending', tx: hash }
    writeJson('wallets.json', wallets)
    const receipt = await pub.waitForTransactionReceipt({ hash })
    w.gift = { status: receipt.status === 'success' ? 'sent' : 'failed', tx: hash }
  } catch (e) {
    w.gift = { status: 'failed', error: String(e.shortMessage || e.message).slice(0, 200) }
  }
  writeJson('wallets.json', wallets)
}

for (const [sub, w] of Object.entries(wallets)) {
  if (w.gift?.status === 'queued') enqueue(() => sendGift(sub))
  if (w.gift?.status === 'pending' && w.gift.tx) {
    enqueue(async () => {
      try {
        const r = await pub.waitForTransactionReceipt({ hash: w.gift.tx })
        w.gift.status = r.status === 'success' ? 'sent' : 'failed'
      } catch {
        w.gift.status = 'failed'
      }
      writeJson('wallets.json', wallets)
    })
  }
}

async function provision(sub, username, name, role, business) {
  let w = wallets[sub]
  if (w) {
    const next = { username: username || w.username, name: name || w.name, role: role || w.role }
    if (business) { next.businessName = business.name; next.businessDescription = business.description }
    if (Object.keys(next).some((k) => next[k] !== w[k])) {
      Object.assign(w, next)
      writeJson('wallets.json', wallets)
    }
  }
  if (!w) {
    const key = generatePrivateKey()
    let createdBlock
    try { createdBlock = Number(await pub.getBlockNumber()) - 50 } catch {}
    w = wallets[sub] = {
      username,
      name,
      role,
      businessName: business?.name ?? '',
      businessDescription: business?.description ?? '',
      address: privateKeyToAccount(key).address,
      privateKey: key,
      createdAt: new Date().toISOString(),
      createdBlock,
      gift: { status: 'queued' },
    }
    writeJson('wallets.json', wallets)
    enqueue(() => sendGift(sub))
  } else if (w.gift?.status === 'failed') {
    w.gift = { status: 'queued' }
    writeJson('wallets.json', wallets)
    enqueue(() => sendGift(sub))
  }
  return { address: w.address, gift: w.gift.status }
}

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'

function decodeMemo(hex) {
  const bytes = Buffer.from(hex.slice(2), 'hex')
  let end = bytes.length
  while (end > 0 && bytes[end - 1] === 0) end--
  if (!end) return null
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, end)) } catch { return hex }
}
const MAX_RANGE = 99_000
const topicOf = (address) => '0x' + address.slice(2).toLowerCase().padStart(64, '0')

async function startBlock(w, latest) {
  if (w.createdBlock != null) return w.createdBlock
  let block = latest - MAX_RANGE
  if (w.gift?.tx) {
    try { block = Number((await pub.getTransactionReceipt({ hash: w.gift.tx })).blockNumber) - 1 } catch {}
  }
  w.createdBlock = block
  writeJson('wallets.json', wallets)
  return block
}

async function history(w) {
  const latest = Number(await pub.getBlockNumber())
  const me = topicOf(w.address)
  const found = new Map()
  const memos = new Map()
  const memoKey = (hash, from, to, amountHex) => `${hash}:${from.toLowerCase()}:${to.toLowerCase()}:${BigInt(amountHex)}`
  for (let start = await startBlock(w, latest); start <= latest; start += MAX_RANGE + 1) {
    const range = { address: OUSD, fromBlock: toHex(start), toBlock: toHex(Math.min(start + MAX_RANGE, latest)) }
    const batches = await Promise.all([
      pub.request({ method: 'eth_getLogs', params: [{ ...range, topics: [TRANSFER_TOPIC, me] }] }),
      pub.request({ method: 'eth_getLogs', params: [{ ...range, topics: [TRANSFER_TOPIC, null, me] }] }),
    ])
    for (const log of batches.flat()) found.set(`${log.transactionHash}:${log.logIndex}`, log)
    const memoBatches = await Promise.all([
      pub.request({ method: 'eth_getLogs', params: [{ ...range, topics: [MEMO_TOPIC, me] }] }),
      pub.request({ method: 'eth_getLogs', params: [{ ...range, topics: [MEMO_TOPIC, null, me] }] }),
    ])
    for (const log of memoBatches.flat()) {
      const from = getAddress('0x' + log.topics[1].slice(-40))
      const to = getAddress('0x' + log.topics[2].slice(-40))
      memos.set(memoKey(log.transactionHash, from, to, log.data), decodeMemo(log.topics[3]))
    }
  }
  const treasuryAddr = treasury.address.toLowerCase()
  return [...found.values()]
    .map((log) => {
      const from = getAddress('0x' + log.topics[1].slice(-40))
      const to = getAddress('0x' + log.topics[2].slice(-40))
      const outgoing = from.toLowerCase() === w.address.toLowerCase()
      const counterparty = outgoing ? to : from
      return {
        hash: log.transactionHash,
        blockNumber: Number(BigInt(log.blockNumber)),
        logIndex: Number(BigInt(log.logIndex)),
        timestamp: log.blockTimestamp ? Number(BigInt(log.blockTimestamp)) : null,
        direction: outgoing ? 'out' : 'in',
        counterparty,
        label: counterparty.toLowerCase() === treasuryAddr ? 'treasury' : null,
        amount: formatUnits(BigInt(log.data), DECIMALS),
        memo: memos.get(memoKey(log.transactionHash, from, to, log.data)) ?? null,
      }
    })
    .sort((a, b) => b.blockNumber - a.blockNumber || b.logIndex - a.logIndex)
}

async function walletDetail(sub) {
  const w = wallets[sub]
  if (!w) return null
  const [balance, txs] = await Promise.all([balanceOf(w.address), history(w)])
  return { address: w.address, balance, symbol: 'OUSD', gift: w.gift, createdAt: w.createdAt, history: txs }
}

async function listWallets() {
  const rows = await Promise.all(
    Object.entries(wallets).map(async ([sub, w]) => {
      let balance = null
      try { balance = await balanceOf(w.address) } catch {}
      return { sub, username: w.username, name: w.name, role: w.role, businessName: w.businessName ?? '', visa: visaPublic(w.visa), address: w.address, balance, createdAt: w.createdAt, gift: w.gift }
    }),
  )
  return rows.sort((a, b) => a.createdAt.localeCompare(b.createdAt))
}

const visaPublic = (v) => (v ? { status: v.status, merchantId: v.merchantId, merchantUrl: v.merchantUrl, error: v.error } : null)
const merchantKeys = readJson('merchant-keys.json', {})
const registering = new Set()

async function loadVisa() {
  try {
    return (await import('../visa-sandbox/visa.mjs')).visa
  } catch {
    return null
  }
}

async function registerMerchant(sub, baseUrl, visaClient) {
  const w = wallets[sub]
  if (!w) return { status: 404, body: { error: 'That user has no wallet.' } }
  if (!/(^|, )merchant($|, )/.test(w.role || '')) return { status: 400, body: { error: 'Only merchants can be registered with Visa.' } }
  if (!w.businessName) return { status: 400, body: { error: 'This merchant has not given a business name.' } }
  if (w.visa?.status === 'registered') return { status: 200, body: { visa: visaPublic(w.visa), already: true } }
  if (typeof baseUrl !== 'string' || !/^https?:\/\/[A-Za-z0-9.:-]+$/.test(baseUrl)) return { status: 400, body: { error: 'A valid base URL is required.' } }
  if (registering.has(sub)) return { status: 409, body: { error: 'A registration for this merchant is already in progress.' } }
  const visa = visaClient ?? (await loadVisa())
  if (!visa) return { status: 503, body: { error: 'Visa credentials are not set up on this machine.' } }

  registering.add(sub)
  const merchantUrl = `${baseUrl}/shop/${encodeURIComponent(w.username)}`
  try {
    const out = await registerMerchantWithVisa({
      visa,
      businessName: w.businessName,
      vmid: sandboxVmid(sub),
      merchantUrl: w.visa?.merchantUrl ?? merchantUrl,
      existing: w.visa?.merchantId ? { merchantId: w.visa.merchantId, keyId: w.visa.keyId } : null,
      onCreated: async ({ merchantId, keyId, privateKeyPem }) => {
        merchantKeys[sub] = { merchantId, keyId, privateKeyPem }
        writeJson('merchant-keys.json', merchantKeys)
        w.visa = { status: 'partial', merchantId, keyId, merchantUrl }
        writeJson('wallets.json', wallets)
      },
    })
    w.visa = { status: 'registered', merchantId: out.merchantId, keyId: out.keyId, merchantUrl: out.merchantUrl, registeredAt: new Date().toISOString() }
    writeJson('wallets.json', wallets)
    return { status: 200, body: { visa: visaPublic(w.visa) } }
  } catch (e) {
    const message = e instanceof VisaRegistrationError ? e.message : 'Could not reach Visa.'
    console.error(`visa registration failed for ${w.username}: ${e instanceof VisaRegistrationError ? message : e}`)
    w.visa = { ...(w.visa ?? {}), status: w.visa?.merchantId ? 'partial' : 'failed', merchantUrl: w.visa?.merchantUrl ?? merchantUrl, error: message }
    writeJson('wallets.json', wallets)
    return { status: 502, body: { error: message, visa: visaPublic(w.visa) } }
  } finally {
    registering.delete(sub)
  }
}

function sendFromTreasury(sub, amount, memoText) {
  const w = wallets[sub]
  if (!w) return Promise.resolve({ status: 404, body: { error: 'That user has no wallet.' } })
  if (typeof amount !== 'string' || !/^\d+(\.\d{1,6})?$/.test(amount) || Number(amount) <= 0) {
    return Promise.resolve({ status: 400, body: { error: 'Amount must be a positive number with at most 6 decimals.' } })
  }
  const memo = memoText == null ? '' : String(memoText).trim()
  if (Buffer.byteLength(memo) > MAX_MEMO_BYTES || /[\u0000-\u001f\u007f]/.test(memo)) {
    return Promise.resolve({ status: 400, body: { error: `Memo must be plain text of at most ${MAX_MEMO_BYTES} bytes.` } })
  }
  const value = parseUnits(amount, DECIMALS)
  return enqueue(async () => {
    try {
      const available = await pub.readContract({ address: OUSD, abi, functionName: 'balanceOf', args: [treasury.address] })
      if (available < value) return { status: 400, body: { error: 'Insufficient treasury balance.' } }
      const hash = memo
        ? await treasuryClient.writeContract({ address: OUSD, abi, functionName: 'transferWithMemo', args: [w.address, value, stringToHex(memo, { size: 32 })] })
        : await treasuryClient.writeContract({ address: OUSD, abi, functionName: 'transfer', args: [w.address, value] })
      const receipt = await pub.waitForTransactionReceipt({ hash })
      if (receipt.status !== 'success') return { status: 502, body: { error: 'The transfer was rejected on-chain.', hash } }
      return { status: 200, body: { hash, amount, memo: memo || null, recipient: { username: w.username, name: w.name, role: w.role, address: w.address } } }
    } catch (e) {
      return { status: 502, body: { error: String(e.shortMessage || e.message).slice(0, 200) } }
    }
  })
}


// ── Proof that the user signed in: Keycloak's own signature, not the app's word ────────────────────────────────
// Granting a mandate or approving a cart requires an ID token from a sign-in that happened just now, whose `nonce`
// is a hash of the exact terms. We check Keycloak's signature on it. A stolen service token alone cannot mint either.
// WALLET_DEV_UNPROVEN=1 switches this off for test tooling (scenarios.mjs); such records are marked as unproven.
const KC_LOCAL = (process.env.KC_LOCAL_URL || 'http://localhost:8080').replace(/\/$/, '')
const KC_REALM = process.env.KC_REALM || 'passkey-demo'
const KC_CLIENT = process.env.KC_CLIENT_ID || 'demo-app'
const DEV_UNPROVEN = process.env.WALLET_DEV_UNPROVEN === '1'
if (DEV_UNPROVEN) console.warn('WARNING: WALLET_DEV_UNPROVEN=1. Mandates and approvals are accepted WITHOUT a Keycloak sign-in proof. For test tooling only.')

let oidcCache = null
async function oidcKeys(force = false) {
  if (!force && oidcCache && Date.now() - oidcCache.at < 600_000) return oidcCache
  const base = `${KC_LOCAL}/realms/${KC_REALM}`
  const jwks = await (await fetch(`${base}/protocol/openid-connect/certs`, { signal: AbortSignal.timeout(8000) })).json()
  const issuer = process.env.KC_ISSUER || (await (await fetch(`${base}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(8000) })).json()).issuer
  return (oidcCache = { issuer, jwks, at: Date.now() })
}
async function verifyProof(idToken, { sub, nonce }) {
  let cfg
  try { cfg = await oidcKeys() } catch { return { ok: false, status: 503, error: 'Cannot reach Keycloak to verify your sign-in.' } }
  const check = () => verifyIdToken(idToken, { jwks: cfg.jwks, issuer: cfg.issuer, audience: KC_CLIENT })
  let r = check()
  if (!r.ok && r.reason === 'unknown signing key') { try { cfg = await oidcKeys(true); r = check() } catch {} }   // keys may have rotated
  if (!r.ok) return { ok: false, status: 400, error: `Your sign-in proof was refused: ${r.reason}.` }
  const c = r.claims
  if (c.sub !== sub) return { ok: false, status: 400, error: 'That sign-in belongs to a different account.' }
  if (c.nonce !== nonce) return { ok: false, status: 400, error: 'That sign-in was not for these exact terms.' }
  const age = Math.floor(Date.now() / 1000) - Number(c.auth_time)
  if (!Number.isFinite(age) || age < -30 || age > AUTH_FRESH_SECONDS) return { ok: false, status: 400, error: 'A fresh sign-in is required: yours is too old.' }
  return { ok: true, proof: { idToken, verifiedAt: new Date().toISOString() } }
}

// ── Mandates, orders and the verifying checkout ────────────────────────────────
const userKeys = readJson('user-keys.json', {})
const mandateStore = readJson('mandates.json', {})
const orderStore = readJson('orders.json', {})
const approvalStore = readJson('approvals.json', {})
const receiptKeys = readJson('receipt-keys.json', {})   // per-store key that signs mandate and payment receipts
const QUOTE_TTL_MS = Number(process.env.WALLET_QUOTE_TTL_SECONDS || 300) * 1000
const APPROVAL_TTL_MS = 15 * 60 * 1000
const tapNonces = new Map()
const usedClosed = new Set(Object.values(orderStore).flatMap((o) => [o.closedId, `n:${o.closedNonce}`]))

const isMerchantWallet = (w) => /(^|, )merchant($|, )/.test(w.role || '')
const merchantByUsername = (name) => Object.values(wallets).find((w) => String(w.username).toLowerCase() === String(name).toLowerCase() && isMerchantWallet(w))
const merchantsList = () => Object.values(wallets).filter(isMerchantWallet).map((w) => ({ username: w.username, businessName: w.businessName || w.username }))

function receiptKeyFor(username) {
  const k = String(username).toLowerCase()
  if (!receiptKeys[k]) { receiptKeys[k] = generateUserKey(); writeJson('receipt-keys.json', receiptKeys) }
  return receiptKeys[k]
}

function ensureUserKey(sub) {
  if (!userKeys[sub]) { userKeys[sub] = generateUserKey(); writeJson('user-keys.json', userKeys) }
  return userKeys[sub]
}

// An unpaid quote that has expired stops counting against the budget.
const orderStatus = (o) => (o.status === 'payment_required' && Date.now() >= Date.parse(o.expiresAt) ? 'expired' : o.status)
const spentMicro = (mandateId) => Object.values(orderStore)
  .filter((o) => o.mandateId === mandateId && ['payment_required', 'paying', 'paid'].includes(orderStatus(o)))
  .reduce((sum, o) => sum + toMicro(o.amount), 0n)

function mandateView(rec, { withJws = false } = {}) {
  const now = Math.floor(Date.now() / 1000)
  const c = rec.constraints
  const spent = spentMicro(rec.id)
  const status = rec.status === 'revoked' ? 'revoked' : now >= rec.exp ? 'expired' : 'active'
  return {
    id: rec.id, agentId: rec.agentId, agentName: agentKeys[rec.agentId]?.name ?? rec.agentId, status,
    createdAt: rec.createdAt, expiresAt: new Date(rec.exp * 1000).toISOString(), revokedAt: rec.revokedAt ?? null,
    merchants: c.merchants, maxPerPurchase: c.maxPerPurchase, budget: c.budget, currency: c.currency,
    spent: fromMicro(spent), remaining: fromMicro((toMicro(c.budget) ?? 0n) - spent),
    ...(withJws ? { jws: rec.jws } : {}),
  }
}

async function createMandate({ sub, agentId, merchants, maxPerPurchase, budget, hours, proof }) {
  const agent = agentKeys[agentId]
  if (!agent) return { status: 404, body: { error: 'No such agent.' } }
  const known = new Set(merchantsList().map((m) => m.username))
  if (!Array.isArray(merchants) || !merchants.length || !merchants.every((m) => known.has(m))) return { status: 400, body: { error: 'Choose at least one store from the list.' } }
  const max = toMicro(maxPerPurchase), total = toMicro(budget)
  if (!max || !total || max <= 0n || total <= 0n) return { status: 400, body: { error: 'Limits must be positive amounts with at most 6 decimals.' } }
  if (max > total) return { status: 400, body: { error: 'The per-purchase limit cannot be more than the total budget.' } }
  if (!Number.isInteger(hours) || hours < 1 || hours > 720) return { status: 400, body: { error: 'Choose a duration between 1 hour and 30 days.' } }
  const terms = mandateTerms({ sub, agentId, merchants, maxPerPurchase, budget, hours })
  let kept = { mode: 'dev-unproven' }
  if (!DEV_UNPROVEN) {
    const v = await verifyProof(proof?.idToken, { sub, nonce: termsHash(terms) })
    if (!v.ok) return { status: v.status, body: { error: v.error } }
    kept = v.proof
  }
  const constraints = { merchants, maxPerPurchase, budget, currency: 'OUSD' }
  const merchantNames = Object.fromEntries(merchants.map((u) => [u, merchantByUsername(u)?.businessName || u]))
  const open = createOpenMandate({ user: ensureUserKey(sub), userSub: sub, agent: { id: agentId, publicJwk: agent.publicJwk }, constraints: { ...constraints, merchantNames }, ttlSeconds: hours * 3600 })
  mandateStore[open.id] = { id: open.id, sub, agentId, constraints, jws: open.jws, exp: open.payload.exp, createdAt: new Date().toISOString(), status: 'active', proof: kept }
  writeJson('mandates.json', mandateStore)
  return { status: 200, body: mandateView(mandateStore[open.id]) }
}

// Human-present stores: the agent's checkout opens an approval; the user approves the exact cart in the app
// (with a fresh passkey sign-in) and then the agent's retry goes through.
function approvalView(a) {
  const status = a.status === 'pending' && Date.now() >= Date.parse(a.expiresAt) ? 'expired' : a.status
  return { id: a.id, status, agentId: a.agentId, agentName: agentKeys[a.agentId]?.name ?? a.agentId, merchant: a.merchant,
    businessName: wallets && Object.values(wallets).find((w) => w.username === a.merchant)?.businessName || a.merchant,
    sku: a.sku, item: a.item, amount: a.amount, currency: a.currency, mandateId: a.mandateId, orderHash: a.orderHash,
    createdAt: a.createdAt, expiresAt: a.expiresAt, decidedAt: a.decidedAt ?? null }
}
const approvalLive = (a) => Date.now() < Date.parse(a.expiresAt)
// An approval is spent when the purchase is PAID, not when it is quoted. While a quote is open it is reserved for that
// order, so one approval can never buy twice; if the quote expires or the payment fails it is free again until it lapses.
const holdsLiveQuote = (a) => { const o = a.orderId && orderStore[a.orderId]; return Boolean(o) && ['payment_required', 'paying'].includes(orderStatus(o)) }
function approvalFor(hash, mandateId) {
  const candidates = Object.values(approvalStore)
    .filter((a) => a.orderHash === hash && a.mandateId === mandateId && approvalLive(a) && a.status !== 'used')
    .sort((x, y) => y.createdAt.localeCompare(x.createdAt))
  const approved = candidates.filter((a) => a.status === 'approved')
  const free = approved.find((a) => !holdsLiveQuote(a))
  if (free) return free
  const held = approved.find(holdsLiveQuote)
  if (held) return { ...held, status: 'reserved' }
  return candidates[0] ?? null
}
function openApproval({ mandateId, order, orderHash: hash, merchant, item }) {
  const rec = mandateStore[mandateId]
  if (!rec) return null
  const id = `apr_${randomBytes(6).toString('hex')}`
  approvalStore[id] = { id, sub: rec.sub, agentId: rec.agentId, mandateId, merchant, sku: order.sku, item: String(item ?? order.sku).slice(0, 80),
    amount: order.amount, currency: order.currency, orderHash: hash, status: 'pending', createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString() }
  writeJson('approvals.json', approvalStore)
  return approvalStore[id]
}
async function decideApproval(id, { sub, decision, authTime, idToken }) {
  const a = approvalStore[id]
  if (!a || a.sub !== sub) return { status: 404, body: { error: 'No such approval request.' } }
  const view = approvalView(a)
  if (view.status !== 'pending') return { status: 409, body: { error: `This request is ${view.status}.` } }
  if (decision === 'approve') {
    if (DEV_UNPROVEN) {
      const age = Math.floor(Date.now() / 1000) - Number(authTime)
      if (!Number.isFinite(age) || age < -30 || age > AUTH_FRESH_SECONDS) return { status: 400, body: { error: 'A fresh passkey sign-in is required to approve.' } }
      a.proof = { mode: 'dev-unproven' }
    } else {
      const v = await verifyProof(idToken, { sub, nonce: termsHash(approvalTerms({ approvalId: a.id, orderHash: a.orderHash, mandateId: a.mandateId })) })
      if (!v.ok) return { status: v.status, body: { error: v.error } }
      a.proof = v.proof
    }
    a.status = 'approved'
    a.expiresAt = new Date(Date.now() + APPROVAL_TTL_MS).toISOString()   // valid for a while after you approve, so a retry needs no new approval
  } else { a.status = 'rejected' }
  a.decidedAt = new Date().toISOString()
  writeJson('approvals.json', approvalStore)
  return { status: 200, body: approvalView(a) }
}

function verifyCheckout(username, input) {
  const m = merchantByUsername(username)
  if (!m) return { status: 404, body: { error: 'No such merchant.' } }
  const { request, order, mandates, policy, meta, issuer } = input ?? {}
  const iss = typeof issuer === 'string' && /^https?:\/\/[^\s]{1,280}$/.test(issuer) ? issuer : `merchant:${m.username}`
  const okStr = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max
  if (!request || !okStr(request.authority, 253) || !okStr(request.path, 2000) || typeof request.headers !== 'object' || !order || order.merchant !== m.username
      || !okStr(order.sku, 40) || !okStr(order.amount, 32) || order.currency !== 'OUSD' || order.quantity !== 1) {
    return { status: 400, body: { error: 'Malformed checkout verification request.' } }
  }
  const result = evaluateCheckout({
    request: { authority: request.authority, path: request.path, headers: Object.fromEntries(Object.entries(request.headers).map(([k, v]) => [k.toLowerCase(), String(v)])) },
    order, mandates: mandates ?? {}, merchant: { username: m.username, address: m.address }, policy: policy ?? { mode: 'autonomous' },
    lookups: {
      agentPublicJwk: (id) => Object.values(agentKeys).find((k) => k.keyid === id)?.publicJwk ?? null,
      userPublicJwk: (sub) => userKeys[sub]?.publicJwk ?? null,
      mandateRecord: (id) => mandateStore[id] ?? null,
      spentMicro, seenNonces: tapNonces, usedClosed, approvalFor,
    },
  })
  const agent = result.context.keyid ? Object.values(agentKeys).find((k) => k.keyid === result.context.keyid) : null
  const body = { ok: result.ok, code: result.code, checks: result.checks, agent: agent?.name ?? null, mandateId: result.context.mandateId ?? null }
  // A signed Mandate Receipt for every decision made on a mandate we could verify (not for identity failures).
  let mandateReceipt = null
  if (result.context.referenceHash && result.status !== 401) {
    const failed = result.checks.find((c) => !c.ok)
    mandateReceipt = createMandateReceipt({ issuer: iss, key: receiptKeyFor(m.username), reference: result.context.referenceHash,
      ...(result.ok ? {} : { error: mandateErrorCode(failed.name, failed.detail), description: failed.detail }) }).jws
    body.receipts = { mandate: mandateReceipt }
  }
  if (!result.ok) {
    let approval = result.context.approvalId ? approvalStore[result.context.approvalId] : null
    if (result.context.needsApproval) approval = openApproval({ mandateId: result.context.mandateId, order, orderHash: result.context.orderHash, merchant: m.username, item: meta?.name })
    return { status: 200, body: { ...body, httpStatus: result.status, ...(approval ? { approval: approvalView(approval) } : {}) } }
  }
  const id = `ord_${randomBytes(6).toString('hex')}`
  if (result.context.approvalId) { approvalStore[result.context.approvalId].orderId = id; writeJson('approvals.json', approvalStore) }   // reserved until paid
  const created = Date.now()
  orderStore[id] = { id, sub: mandateStore[result.context.mandateId].sub, mandateId: result.context.mandateId, agentId: result.context.agentId, merchant: m.username,
    sku: order.sku, item: String(meta?.name ?? order.sku).slice(0, 80), amount: order.amount, currency: 'OUSD', status: 'payment_required',
    createdAt: new Date(created).toISOString(), expiresAt: new Date(created + QUOTE_TTL_MS).toISOString(), issuer: iss,
    closedId: result.context.closedId, closedNonce: result.context.closedNonce, closedHash: result.context.closedHash, approvalId: result.context.approvalId ?? null, mandateReceipt,
    closedJws: mandates.closed, request: { authority: request.authority, path: request.path, headers: { 'signature-input': request.headers['signature-input'] ?? request.headers['Signature-Input'], signature: request.headers.signature ?? request.headers.Signature } } }
  usedClosed.add(result.context.closedId); usedClosed.add(`n:${result.context.closedNonce}`)
  writeJson('orders.json', orderStore)
  return { status: 200, body: { ...body, httpStatus: 402, orderId: id, payment: { payTo: m.address, amount: order.amount, currency: 'OUSD', network: 'Tempo testnet', reference: id, memo: id, expiresAt: orderStore[id].expiresAt } } }
}

// ── Payment: the user's wallet pays against a valid order; the store confirms it on-chain and signs a receipt. ──
const businessOf = (username) => merchantsList().find((x) => x.username === username)?.businessName ?? username
function orderView(o) {
  // Whether each receipt's signature checks out against the store's key: true, false, or null when there is no such receipt.
  const verified = (jws, typ) => (jws ? verifyJws(jws, receiptKeyFor(o.merchant).publicJwk, typ).ok : null)
  return { id: o.id, status: orderStatus(o), agentId: o.agentId, agentName: agentKeys[o.agentId]?.name ?? o.agentId, merchant: o.merchant, businessName: businessOf(o.merchant),
    sku: o.sku, item: o.item ?? o.sku, amount: o.amount, currency: o.currency, mandateId: o.mandateId, createdAt: o.createdAt, expiresAt: o.expiresAt,
    txHash: o.txHash ?? null, blockNumber: o.blockNumber ?? null, paidAt: o.paidAt ?? null, error: o.error ?? null, approved: Boolean(o.approvalId),
    verified: { mandate: verified(o.mandateReceipt, MANDATE_RECEIPT_TYP), payment: verified(o.paymentReceipt, PAYMENT_RECEIPT_TYP) },
    receipts: { ...(o.mandateReceipt ? { mandate: o.mandateReceipt } : {}), ...(o.paymentReceipt ? { payment: o.paymentReceipt } : {}) } }
}

// The store's side: look at the chain and decide whether this transaction pays this order.
async function confirmPayment(orderId, txHash, merchantUsername) {
  const o = orderStore[orderId]
  if (!o || (merchantUsername && o.merchant.toLowerCase() !== String(merchantUsername).toLowerCase())) return { status: 404, body: { error: 'No such order.' } }
  if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return { status: 400, body: { error: 'txHash must be a 0x-prefixed 32-byte hash.' } }
  if (o.status === 'paid') return o.txHash === txHash ? { status: 200, body: orderView(o) } : { status: 409, body: { error: 'This order was already paid with a different transaction.' } }
  if (!['payment_required', 'paying'].includes(o.status)) return { status: 409, body: { error: `This order is ${orderStatus(o)}.` } }
  if (Object.values(orderStore).some((x) => x.id !== o.id && x.txHash === txHash)) return { status: 409, body: { error: 'That transaction already paid another order.' } }
  let receipt
  try { receipt = await pub.waitForTransactionReceipt({ hash: txHash, timeout: 30_000 }) } catch { return { status: 404, body: { error: 'That transaction was not found, or is not confirmed yet.' } } }
  const key = receiptKeyFor(o.merchant)
  if (receipt.status !== 'success') {
    o.status = 'failed'; o.txHash = txHash; o.error = 'The transaction failed on-chain.'
    o.paymentReceipt = createPaymentReceipt({ issuer: o.issuer, key, reference: o.closedHash, paymentId: o.id, error: 'payment_failed', description: o.error }).jws
    writeJson('orders.json', orderStore)
    return { status: 400, body: { error: o.error, ...orderView(o) } }
  }
  const payer = wallets[o.sub]
  const merchant = merchantByUsername(o.merchant)
  const found = findPayment({ logs: receipt.logs, token: OUSD, payer: payer?.address, payee: merchant?.address, amountMicro: toMicro(o.amount), memo: o.id })
  if (!found.ok) return { status: 400, body: { error: `That transaction does not pay this order: ${found.reason}.` } }
  o.status = 'paid'; o.txHash = txHash; o.paidAt = new Date().toISOString(); delete o.error
  o.blockNumber = Number(receipt.blockNumber); o.payer = payer.address; o.payee = merchant.address
  if (o.approvalId && approvalStore[o.approvalId]) { approvalStore[o.approvalId].status = 'used'; writeJson('approvals.json', approvalStore) }   // now it is spent
  o.paymentReceipt = createPaymentReceipt({ issuer: o.issuer, key, reference: o.closedHash, paymentId: o.id, txHash }).jws
  writeJson('orders.json', orderStore)
  return { status: 200, body: orderView(o) }
}

// Everything a third party needs to check one purchase, with no access to our database.
async function buildEvidence(o) {
  const rec = mandateStore[o.mandateId]
  const ap = o.approvalId ? approvalStore[o.approvalId] : null
  const uk = userKeys[o.sub]
  const sk = receiptKeyFor(o.merchant)
  const agent = agentKeys[o.agentId]
  let oidc = null
  try { const c = await oidcKeys(); oidc = { issuer: c.issuer, audience: KC_CLIENT, jwks: c.jwks } } catch {}
  return {
    version: EVIDENCE_VERSION, generatedAt: new Date().toISOString(),
    order: { id: o.id, merchant: o.merchant, sku: o.sku, item: o.item, amount: o.amount, currency: o.currency, quantity: 1, status: orderStatus(o), createdAt: o.createdAt, paidAt: o.paidAt ?? null, txHash: o.txHash ?? null },
    mandates: { open: rec?.jws ?? null, closed: o.closedJws ?? null },
    request: o.request ?? null,
    receipts: { mandate: o.mandateReceipt ?? null, payment: o.paymentReceipt ?? null },
    grant: { proof: rec?.proof ? (rec.proof.idToken ? { idToken: rec.proof.idToken } : { mode: rec.proof.mode }) : null },
    approval: ap ? { id: ap.id, createdAt: ap.createdAt, decidedAt: ap.decidedAt ?? null, proof: ap.proof?.idToken ? { idToken: ap.proof.idToken } : ap.proof ?? null } : null,
    chain: { network: 'Tempo testnet (Moderato)', chainId: chain.id, rpc: RPC, token: OUSD, payer: o.payer ?? wallets[o.sub]?.address ?? null, payee: o.payee ?? merchantByUsername(o.merchant)?.address ?? null, txHash: o.txHash ?? null, blockNumber: o.blockNumber ?? null },
    keys: { user: { sub: o.sub, jwk: uk?.publicJwk ?? null }, agent: { id: o.agentId, kid: agent?.keyid ?? null, jwk: agent?.publicJwk ?? null }, store: { username: o.merchant, kid: sk.kid, jwk: sk.publicJwk }, oidc },
  }
}

// What a store may show the public: paid orders only, no names of users or agents.
const publicHistory = (username) => Object.values(orderStore)
  .filter((o) => o.merchant.toLowerCase() === String(username).toLowerCase() && o.status === 'paid')
  .sort((a, b) => String(b.paidAt).localeCompare(String(a.paidAt))).slice(0, 25)
  .map((o) => ({ id: o.id, item: o.item ?? o.sku, sku: o.sku, amount: o.amount, currency: o.currency, txHash: o.txHash, paidAt: o.paidAt }))

// The wallet's side: the agent asks to pay a quoted order. Refused unless the quote is live and the mandate still holds.
async function payOrder(agentId, orderId) {
  const o = orderStore[orderId]
  if (!o || o.agentId !== agentId) return { status: 404, body: { error: 'No such order for this agent.' } }
  const st = orderStatus(o)
  if (st === 'paid') return { status: 200, body: { ...orderView(o), already: true } }
  if (st === 'paying') return { status: 409, body: { error: 'This order is already being paid.' } }
  if (st !== 'payment_required') return { status: 409, body: { error: `This order is ${st}: ask the store for a new quote.` } }
  const mv = mandateStore[o.mandateId] ? mandateView(mandateStore[o.mandateId]) : null
  if (!mv || mv.status !== 'active') return { status: 403, body: { error: `The mandate is ${mv?.status ?? 'unknown'}: the agent may no longer pay.` } }
  const w = wallets[o.sub]
  const merchant = merchantByUsername(o.merchant)
  if (!w || !merchant) return { status: 400, body: { error: 'The payer or the store has no wallet.' } }
  const amount = toMicro(o.amount)
  o.status = 'paying'; writeJson('orders.json', orderStore)
  let hash
  try {
    hash = await enqueue(async () => {
      const bal = await pub.readContract({ address: OUSD, abi, functionName: 'balanceOf', args: [w.address] })
      const floorCents = (m) => fromMicro(m - (m % 10_000n))   // never state a balance as more than the wallet holds
      if (bal < amount) throw Object.assign(new Error(`Insufficient balance: the wallet holds ${floorCents(bal)} OUSD and this costs ${o.amount} OUSD.`), { userFacing: true })
      const client = createWalletClient({ account: privateKeyToAccount(w.privateKey), chain, transport: rpcHttp(RPC) })
      return client.writeContract({ address: OUSD, abi, functionName: 'transferWithMemo', args: [merchant.address, amount, stringToHex(o.id, { size: MAX_MEMO_BYTES })] })
    })
  } catch (e) {
    if (e.userFacing) {
      // The buyer cannot cover it: cancel the quote (it stops counting against the budget) and record the failure in a signed
      // receipt. The approval is kept, so the agent can be sent again without asking the buyer for a new one.
      o.status = 'failed'; o.error = e.message
      o.paymentReceipt = createPaymentReceipt({ issuer: o.issuer, key: receiptKeyFor(o.merchant), reference: o.closedHash, paymentId: o.id, error: 'insufficient_funds', description: e.message }).jws
      writeJson('orders.json', orderStore)
      return { status: 400, body: { error: e.message, ...orderView(o) } }
    }
    o.status = 'payment_required'; writeJson('orders.json', orderStore)   // nothing was sent: the quote stays payable until it expires
    return { status: 502, body: { error: String(e.shortMessage || e.message).slice(0, 200) } }
  }
  o.txHash = hash; writeJson('orders.json', orderStore)                   // remember it before waiting, so a restart can finish the job
  const out = await confirmPayment(o.id, hash, o.merchant)
  return out.status === 200 ? out : { status: 502, body: { ...out.body, txHash: hash, note: 'The transfer was sent; confirmation will be retried.' } }
}

// Older records marked an approval spent as soon as it was quoted. If that purchase was never paid, give the approval back.
for (const a of Object.values(approvalStore)) {
  if (a.status !== 'used') continue
  const o = Object.values(orderStore).find((x) => x.approvalId === a.id)
  if (o && o.status !== 'paid') { a.status = 'approved'; a.orderId = o.id; writeJson('approvals.json', approvalStore) }
}

// After a restart, finish any order that was mid-payment.
for (const o of Object.values(orderStore)) {
  if (o.status !== 'paying') continue
  if (!o.txHash) { o.status = 'payment_required'; writeJson('orders.json', orderStore) } else enqueue(() => confirmPayment(o.id, o.txHash, o.merchant).catch(() => {}))
}

function signClosedMandate(agentId, { openJws, order, payee }) {
  const agent = agentKeys[agentId]
  const d = decodeJws(openJws)
  const rec = d && mandateStore[d.payload?.jti]
  if (!agent || !rec || rec.agentId !== agentId || rec.jws !== openJws) return { status: 400, body: { error: 'That open mandate does not belong to this agent.' } }
  const view = mandateView(rec)
  if (view.status !== 'active') return { status: 400, body: { error: `That mandate is ${view.status}.` } }
  if (!order || typeof order !== 'object' || !/^0x[0-9a-fA-F]{40}$/.test(payee || '')) return { status: 400, body: { error: 'order and payee required.' } }
  return { status: 200, body: { jws: createClosedMandate({ agentKey: agent, openJws, order, payee }).jws } }
}

const send = (res, status, body) => {
  const text = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  res.end(text)
}
const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (c) => { data += c; if (data.length > 40_000) reject(new Error('body too large')) })
    req.on('end', () => resolve(data))
  })

http.createServer(async (req, res) => {
  const given = Buffer.from(String(req.headers['x-wallet-token'] || ''))
  if (given.length !== TOKEN.length || !timingSafeEqual(given, TOKEN)) return send(res, 401, { error: 'unauthorized' })
  try {
    if (req.method === 'GET' && req.url === '/treasury') {
      return send(res, 200, { address: treasury.address, symbol: 'OUSD', balance: await balanceOf(treasury.address) })
    }
    if (req.method === 'GET' && req.url === '/wallets') {
      return send(res, 200, { wallets: await listWallets() })
    }
    const url = new URL(req.url, 'http://localhost')
    if (req.method === 'GET' && url.pathname === '/merchants') return send(res, 200, { merchants: merchantsList() })
    if (req.method === 'GET' && url.pathname === '/mandates') {
      const sub = url.searchParams.get('sub')
      if (!sub) return send(res, 400, { error: 'sub required' })
      const mine = Object.values(mandateStore).filter((r) => r.sub === sub).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((r) => mandateView(r))
      return send(res, 200, { mandates: mine })
    }
    if (req.method === 'GET' && url.pathname === '/approvals') {
      const sub = url.searchParams.get('sub')
      if (!sub) return send(res, 400, { error: 'sub required' })
      const mine = Object.values(approvalStore).filter((a) => a.sub === sub).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(approvalView)
      return send(res, 200, { approvals: mine })
    }
    const approval = url.pathname.match(/^\/approvals\/(apr_[0-9a-f]{12})(?:\/(approve|reject))?$/)
    if (approval && req.method === 'GET' && !approval[2]) {
      const a = approvalStore[approval[1]]
      if (!a || a.sub !== url.searchParams.get('sub')) return send(res, 404, { error: 'No such approval request.' })
      return send(res, 200, approvalView(a))
    }
    if (approval && approval[2] && req.method === 'POST') {
      const { sub, authTime, idToken } = JSON.parse((await readBody(req)) || '{}')
      const out = await decideApproval(approval[1], { sub, decision: approval[2], authTime, idToken })
      return send(res, out.status, out.body)
    }
    if (req.method === 'POST' && url.pathname === '/mandates') {
      const out = await createMandate(JSON.parse((await readBody(req)) || '{}'))
      return send(res, out.status, out.body)
    }
    const revoke = req.method === 'POST' && url.pathname.match(/^\/mandates\/(mnd_[0-9a-f]{12})\/revoke$/)
    if (revoke) {
      const { sub } = JSON.parse((await readBody(req)) || '{}')
      const rec = mandateStore[revoke[1]]
      if (!rec || rec.sub !== sub) return send(res, 404, { error: 'No such mandate.' })
      if (rec.status !== 'revoked') { rec.status = 'revoked'; rec.revokedAt = new Date().toISOString(); writeJson('mandates.json', mandateStore) }
      return send(res, 200, mandateView(rec))
    }
    const agentMandates = req.method === 'GET' && url.pathname.match(/^\/agents\/(agt_[0-9a-f]{12})\/mandates$/)
    if (agentMandates) {
      const list = Object.values(mandateStore).filter((r) => r.agentId === agentMandates[1]).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((r) => mandateView(r, { withJws: true }))
      return send(res, 200, { mandates: list })
    }
    const closed = req.method === 'POST' && url.pathname.match(/^\/agents\/(agt_[0-9a-f]{12})\/closed-mandate$/)
    if (closed) {
      const out = signClosedMandate(closed[1], JSON.parse((await readBody(req)) || '{}'))
      return send(res, out.status, out.body)
    }
    const pay = req.method === 'POST' && url.pathname.match(/^\/agents\/(agt_[0-9a-f]{12})\/pay$/)
    if (pay) {
      const { orderId } = JSON.parse((await readBody(req)) || '{}')
      const out = await payOrder(pay[1], String(orderId ?? ''))
      return send(res, out.status, out.body)
    }
    if (req.method === 'GET' && url.pathname === '/orders') {
      const sub = url.searchParams.get('sub')
      if (!sub) return send(res, 400, { error: 'sub required' })
      return send(res, 200, { orders: Object.values(orderStore).filter((o) => o.sub === sub).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(orderView) })
    }
    const evidence = req.method === 'GET' && url.pathname.match(/^\/orders\/(ord_[0-9a-f]{12})\/evidence$/)
    if (evidence) {
      const o = orderStore[evidence[1]]
      return o ? send(res, 200, await buildEvidence(o)) : send(res, 404, { error: 'No such order.' })
    }
    const history = req.method === 'GET' && url.pathname.match(/^\/merchants\/([^/]+)\/orders$/)
    if (history) return send(res, 200, { orders: publicHistory(decodeURIComponent(history[1])) })
    const orderOne = req.method === 'GET' && url.pathname.match(/^\/orders\/(ord_[0-9a-f]{12})$/)
    if (orderOne) {
      const o = orderStore[orderOne[1]]
      return o ? send(res, 200, orderView(o)) : send(res, 404, { error: 'No such order.' })
    }
    const confirm = req.method === 'POST' && url.pathname.match(/^\/merchants\/([^/]+)\/orders\/(ord_[0-9a-f]{12})\/confirm$/)
    if (confirm) {
      const { txHash } = JSON.parse((await readBody(req)) || '{}')
      const out = await confirmPayment(confirm[2], txHash, decodeURIComponent(confirm[1]))
      return send(res, out.status, out.body)
    }
    const verify = req.method === 'POST' && url.pathname.match(/^\/merchants\/([^/]+)\/verify-checkout$/)
    if (verify) {
      const out = verifyCheckout(decodeURIComponent(verify[1]), JSON.parse((await readBody(req)) || '{}'))
      return send(res, out.status, out.body)
    }
    const record = req.method === 'GET' && req.url.match(/^\/merchants\/([^/?]+)\/visa$/)
    if (record) {
      const w = wallets[decodeURIComponent(record[1])]
      if (!w?.visa?.merchantId) return send(res, 404, { error: 'This merchant has no record at Visa yet.' })
      const visa = await loadVisa()
      if (!visa) return send(res, 503, { error: 'Visa credentials are not set up on this machine.' })
      const r = await visa('GET', `/vmrs/v1/merchants/${w.visa.merchantId}`)
      if (r.status !== 200 || !r.json) return send(res, 502, { error: `Visa did not return the record: ${visaDetail(r)}` })
      return send(res, 200, { username: w.username, ourStatus: w.visa.status, record: summarizeVisaMerchant(r.json) })
    }
    const shop = req.method === 'GET' && req.url.match(/^\/merchants\/([^/?]+)$/)
    if (shop) {
      const wanted = decodeURIComponent(shop[1]).toLowerCase()
      const w = Object.values(wallets).find((x) => String(x.username).toLowerCase() === wanted && /(^|, )merchant($|, )/.test(x.role || ''))
      if (!w) return send(res, 404, { error: 'no such merchant' })
      return send(res, 200, { username: w.username, businessName: w.businessName ?? '', businessDescription: w.businessDescription ?? '', address: w.address, visa: visaPublic(w.visa), receiptKey: { ...receiptKeyFor(w.username).publicJwk, kid: receiptKeyFor(w.username).kid, alg: 'EdDSA', use: 'sig' } })
    }
    const one = req.method === 'GET' && req.url.match(/^\/wallets\/([^/?]+)$/)
    if (one) {
      const detail = await walletDetail(decodeURIComponent(one[1]))
      return detail ? send(res, 200, detail) : send(res, 404, { error: 'no wallet' })
    }
    if (req.method === 'POST' && req.url === '/wallets') {
      const { sub, username, name, role, businessName, businessDescription } = JSON.parse((await readBody(req)) || '{}')
      if (typeof sub !== 'string' || !sub || sub.length > 100) return send(res, 400, { error: 'sub required' })
      const clip = (v, n) => String(v || '').slice(0, n)
      const business = businessName === undefined && businessDescription === undefined ? null : { name: clip(businessName, 100).trim(), description: clip(businessDescription, 200).trim() }
      return send(res, 200, await provision(sub, clip(username, 100), clip(name, 100), clip(role, 40), business))
    }
    if (req.method === 'POST' && req.url === '/merchants/register-visa') {
      const { sub, baseUrl } = JSON.parse((await readBody(req)) || '{}')
      const out = await registerMerchant(sub, baseUrl)
      return send(res, out.status, out.body)
    }
    if (req.method === 'GET' && req.url === '/agents/keys') {
      return send(res, 200, { keys: Object.values(agentKeys).map(publicEntry) })
    }
    if (req.method === 'POST' && req.url === '/agents/identity') {
      const { agentId, name } = JSON.parse((await readBody(req)) || '{}')
      if (!/^agt_[0-9a-f]{12}$/.test(agentId || '')) return send(res, 400, { error: 'valid agentId required' })
      return send(res, 200, ensureAgentIdentity(agentId, String(name || '').slice(0, 100)))
    }
    if (req.method === 'POST' && req.url === '/agents/sign') {
      const { agentId, authority, path, tag } = JSON.parse((await readBody(req)) || '{}')
      const k = agentKeys[agentId]
      if (!k) return send(res, 404, { error: 'no identity for that agent' })
      if (!/^[A-Za-z0-9.:-]{1,253}$/.test(authority || '') || !/^\/[\x21-\x7e]{0,2000}$/.test(path || '') || !TAGS.includes(tag)) {
        return send(res, 400, { error: 'authority, path and a valid tag are required' })
      }
      return send(res, 200, { keyid: k.keyid, headers: signRequest({ privateJwk: k.privateJwk, keyid: k.keyid, authority, path, tag }) })
    }
    if (req.method === 'POST' && req.url === '/treasury/send') {
      const { sub, amount, memo } = JSON.parse((await readBody(req)) || '{}')
      const out = await sendFromTreasury(sub, amount, memo)
      return send(res, out.status, out.body)
    }
    return send(res, 404, { error: 'not found' })
  } catch (e) {
    return send(res, 502, { error: String(e.shortMessage || e.message).slice(0, 200) })
  }
}).listen(PORT, '127.0.0.1', () => console.log(`wallet service on http://127.0.0.1:${PORT}  treasury ${treasury.address}`))
