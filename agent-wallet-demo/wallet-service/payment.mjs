// Pure helpers for confirming an OUSD payment from a transaction receipt's logs. No network here: the caller
// fetches the receipt and passes its logs. Tempo's transferWithMemo emits an event whose topics are
// [MEMO_TOPIC, from, to, memo] and whose data is the amount, so one log proves who paid whom, how much, and for what.

export const MEMO_TOPIC = '0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0'
export const MAX_MEMO_BYTES = 32

const addrOf = (topic) => `0x${String(topic).slice(-40)}`.toLowerCase()

// bytes32, right-padded with zeros, the same way viem's stringToHex(text, { size: 32 }) does it.
export function memoTopic(text) {
  const bytes = Buffer.from(String(text), 'utf8')
  if (bytes.length === 0 || bytes.length > MAX_MEMO_BYTES) throw new Error(`memo must be 1 to ${MAX_MEMO_BYTES} bytes`)
  return `0x${bytes.toString('hex').padEnd(64, '0')}`
}

// Returns { ok: true, log } or { ok: false, reason }. All four facts must hold in the same log.
export function findPayment({ logs, token, payer, payee, amountMicro, memo }) {
  const want = memoTopic(memo)
  const sameMemo = (logs ?? []).filter((l) => String(l.address).toLowerCase() === String(token).toLowerCase() && l.topics?.[0] === MEMO_TOPIC && String(l.topics?.[3]).toLowerCase() === want)
  if (!sameMemo.length) return { ok: false, reason: `no OUSD transfer carries the memo ${memo}` }
  for (const log of sameMemo) {
    if (addrOf(log.topics[1]) !== String(payer).toLowerCase()) continue
    if (addrOf(log.topics[2]) !== String(payee).toLowerCase()) continue
    if (BigInt(log.data) !== BigInt(amountMicro)) continue
    return { ok: true, log }
  }
  const l = sameMemo[0]
  if (addrOf(l.topics[1]) !== String(payer).toLowerCase()) return { ok: false, reason: 'the transfer was not made by the mandate holder’s wallet' }
  if (addrOf(l.topics[2]) !== String(payee).toLowerCase()) return { ok: false, reason: 'the transfer went to a different payee' }
  return { ok: false, reason: 'the transfer amount does not match the order' }
}
