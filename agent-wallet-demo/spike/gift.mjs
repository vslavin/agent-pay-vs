import { createPublicClient, createWalletClient, http, defineChain, formatUnits, parseUnits } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { readFileSync } from 'node:fs'

const RPC = 'https://rpc.moderato.tempo.xyz'
const OUSD = '0x20c0000000000000000000006a37da5c996874be'
const chain = defineChain({
  id: 42431,
  name: 'Tempo Testnet (Moderato)',
  nativeCurrency: { name: 'n/a', symbol: 'n/a', decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
})
const abi = [
  { name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] },
  { name: 'transfer', type: 'function', stateMutability: 'nonpayable', inputs: [{ type: 'address' }, { type: 'uint256' }], outputs: [{ type: 'bool' }] },
]

const treasury = privateKeyToAccount(JSON.parse(readFileSync(new URL('./.wallet.json', import.meta.url), 'utf8')).privateKey)
const user = privateKeyToAccount(generatePrivateKey())
const pub = createPublicClient({ chain, transport: http(RPC) })
const wallet = createWalletClient({ account: treasury, chain, transport: http(RPC) })
const bal = async (a) => formatUnits(await pub.readContract({ address: OUSD, abi, functionName: 'balanceOf', args: [a] }), 6)

console.log('treasury:', treasury.address, await bal(treasury.address), 'OUSD')
console.log('new user:', user.address, await bal(user.address), 'OUSD')

const hash = await wallet.writeContract({
  address: OUSD, abi, functionName: 'transfer', args: [user.address, parseUnits('100', 6)],
})
console.log('transfer tx:', hash)
const receipt = await pub.waitForTransactionReceipt({ hash })
console.log('status:', receipt.status, 'block:', receipt.blockNumber)

console.log('treasury after:', await bal(treasury.address), 'OUSD')
console.log('user after:    ', await bal(user.address), 'OUSD')
console.log('explorer:', `https://explore.testnet.tempo.xyz/tx/${hash}`)
