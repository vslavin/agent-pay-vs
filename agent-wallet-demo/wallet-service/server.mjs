import http from 'node:http'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs'
import { createPublicClient, createWalletClient, http as rpcHttp, defineChain, formatUnits, parseUnits, getAddress, toHex, stringToHex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'

const PORT = Number(process.env.WALLET_SERVICE_PORT || 3100)
const RPC = 'https://rpc.moderato.tempo.xyz'
const OUSD = '0x20c0000000000000000000006a37da5c996874be'
const DECIMALS = 6
const GIFT_AMOUNT = '100'

const dataFile = (name) => new URL(`./data/${name}`, import.meta.url)
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

async function provision(sub, username, name, role) {
  let w = wallets[sub]
  if (w) {
    const next = { username: username || w.username, name: name || w.name, role: role || w.role }
    if (next.username !== w.username || next.name !== w.name || next.role !== w.role) {
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
const MEMO_TOPIC = '0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0'
const MAX_MEMO_BYTES = 32

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
      return { sub, username: w.username, name: w.name, role: w.role, address: w.address, balance, createdAt: w.createdAt, gift: w.gift }
    }),
  )
  return rows.sort((a, b) => a.createdAt.localeCompare(b.createdAt))
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

const send = (res, status, body) => {
  const text = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  res.end(text)
}
const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (c) => { data += c; if (data.length > 10_000) reject(new Error('body too large')) })
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
    const one = req.method === 'GET' && req.url.match(/^\/wallets\/([^/?]+)$/)
    if (one) {
      const detail = await walletDetail(decodeURIComponent(one[1]))
      return detail ? send(res, 200, detail) : send(res, 404, { error: 'no wallet' })
    }
    if (req.method === 'POST' && req.url === '/wallets') {
      const { sub, username, name, role } = JSON.parse((await readBody(req)) || '{}')
      if (typeof sub !== 'string' || !sub || sub.length > 100) return send(res, 400, { error: 'sub required' })
      const clip = (v, n) => String(v || '').slice(0, n)
      return send(res, 200, await provision(sub, clip(username, 100), clip(name, 100), clip(role, 40)))
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
