import { test } from 'node:test'
import assert from 'node:assert/strict'
import { findPayment, memoTopic, MEMO_TOPIC } from './payment.mjs'

const TOKEN = '0x20c0000000000000000000006a37da5c996874be'
const PAYER = '0x1111111111111111111111111111111111111111'
const PAYEE = '0x2222222222222222222222222222222222222222'
const pad = (a) => '0x' + a.slice(2).padStart(64, '0')
const log = (over = {}) => ({ address: TOKEN, topics: [MEMO_TOPIC, pad(PAYER), pad(PAYEE), memoTopic('ord_0123456789ab')], data: '0x' + (89_000_000n).toString(16).padStart(64, '0'), ...over })
const ask = (logs, over = {}) => findPayment({ logs, token: TOKEN, payer: PAYER, payee: PAYEE, amountMicro: 89_000_000n, memo: 'ord_0123456789ab', ...over })

test('memo topics are right-padded bytes32 and length-checked', () => {
  assert.equal(memoTopic('ord_1'), '0x6f72645f31' + '0'.repeat(54))
  assert.throws(() => memoTopic(''))
  assert.throws(() => memoTopic('x'.repeat(33)))
})

test('a transfer with the right payer, payee, amount and memo is accepted', () => {
  assert.equal(ask([log()]).ok, true)
})

test('anything different is refused, with a reason', () => {
  assert.match(ask([]).reason, /no OUSD transfer carries the memo/)
  assert.match(ask([log()], { memo: 'ord_ffffffffffff' }).reason, /no OUSD transfer carries the memo/)
  assert.match(ask([log()], { payer: '0x3333333333333333333333333333333333333333' }).reason, /not made by/)
  assert.match(ask([log()], { payee: '0x3333333333333333333333333333333333333333' }).reason, /different payee/)
  assert.match(ask([log()], { amountMicro: 90_000_000n }).reason, /amount/)
  assert.match(ask([log({ address: '0x4444444444444444444444444444444444444444' })]).reason, /no OUSD transfer/)
})

test('one matching log among others is enough', () => {
  assert.equal(ask([log({ data: '0x01' }), log()]).ok, true)
})
