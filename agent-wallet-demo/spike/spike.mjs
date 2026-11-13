import { createPublicClient, http, defineChain, formatUnits } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs'

const RPC = 'https://rpc.moderato.tempo.xyz'
const OUSD = '0x20c0000000000000000000006a37da5c996874be'
const WALLET_FILE = new URL('./.wallet.json', import.meta.url)

const tempoTestnet = defineChain({
  id: 42431,
  name: 'Tempo Testnet (Moderato)',
  nativeCurrency: { name: 'n/a', symbol: 'n/a', decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
})
const client = createPublicClient({ chain: tempoTestnet, transport: http(RPC) })

const erc20 = [
  { name: 'symbol', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { name: 'decimals', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] },
]

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  return res.json()
}

async function balance(address) {
  const [symbol, decimals, raw] = await Promise.all([
    client.readContract({ address: OUSD, abi: erc20, functionName: 'symbol' }),
    client.readContract({ address: OUSD, abi: erc20, functionName: 'decimals' }),
    client.readContract({ address: OUSD, abi: erc20, functionName: 'balanceOf', args: [address] }),
  ])
  return { symbol, decimals, raw, human: formatUnits(raw, decimals) }
}

console.log('1. chain id:', await client.getChainId(), '(expect 42431)')

let key
if (existsSync(WALLET_FILE)) {
  key = JSON.parse(readFileSync(WALLET_FILE, 'utf8')).privateKey
  console.log('2. reusing throwaway wallet from .wallet.json')
} else {
  key = generatePrivateKey()
  writeFileSync(WALLET_FILE, JSON.stringify({ privateKey: key }, null, 2))
  chmodSync(WALLET_FILE, 0o600)
  console.log('2. created throwaway testnet wallet (key saved to .wallet.json, git-ignored)')
}
const account = privateKeyToAccount(key)
console.log('   address:', account.address)

const before = await balance(account.address)
console.log(`3. before funding: ${before.human} ${before.symbol} (decimals ${before.decimals})`)

if (before.raw === 0n) {
  const out = await rpc('tempo_fundAddress', [account.address])
  console.log('4. faucet (tempo_fundAddress) response:', JSON.stringify(out).slice(0, 400))
  await new Promise((r) => setTimeout(r, 4000))
} else {
  console.log('4. already funded, skipping faucet')
}

const after = await balance(account.address)
console.log(`5. after funding:  ${after.human} ${after.symbol}`)
console.log(after.raw > 0n ? 'RESULT: OUSD test token received' : 'RESULT: no OUSD received')
console.log('explorer:', `https://explore.testnet.tempo.xyz/address/${account.address}`)
