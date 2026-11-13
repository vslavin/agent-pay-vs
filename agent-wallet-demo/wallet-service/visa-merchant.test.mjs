import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPublicKey } from 'node:crypto'
import { registerMerchantWithVisa, VisaRegistrationError, detail, sandboxVmid, summarizeVisaMerchant } from './visa-merchant.mjs'

test('the placeholder VMID is 11 digits, stable per merchant, different between merchants', () => {
  const a = sandboxVmid('3112708a-234c-4fb7-8220-988fb2ad86ed')
  assert.match(a, /^9\d{10}$/)
  assert.equal(a, sandboxVmid('3112708a-234c-4fb7-8220-988fb2ad86ed'))
  assert.notEqual(a, sandboxVmid('fde80aad-7b49-4c56-bd84-383ac917b60a'))
})

test('error details are readable text, never [object Object]', () => {
  const list = detail({ status: 422, json: { detail: [{ loc: ['body', 'merchantUrl'], msg: 'invalid URL', type: 'value_error' }, { loc: ['body', 'encryptionKey', 'encryptionKey'], msg: 'not a valid key', type: 'value_error' }] } })
  assert.equal(list, 'HTTP 422 - body.merchantUrl: invalid URL; body.encryptionKey.encryptionKey: not a valid key')
  assert.equal(detail({ status: 409, json: { detail: 'merchantUrl exists' } }), 'HTTP 409 - merchantUrl exists')
  assert.equal(detail({ status: 401, json: { responseStatus: { code: '9159', message: 'Token Validation Failed' } } }), 'HTTP 401 - 9159 Token Validation Failed')
  assert.equal(detail({ status: 400, json: { detail: { field: 'x' } } }), 'HTTP 400 - {"field":"x"}')
  assert.equal(detail({ status: 500, json: null, text: '' }), 'HTTP 500')
  assert.equal(detail({ status: 502, json: null, text: '<html>Bad gateway</html>' }), 'HTTP 502 - <html>Bad gateway</html>')
  assert.ok(!/object Object/.test(detail({ status: 422, json: { detail: [{ weird: true }] } })))
})

const MID = '7f4c82a1-305e-4f9c-8d2a-1b3e5f7c502a'
const KID = 'a1b2c384-56c7-48d9-be0f-1e2d3c4b5a6f'
const args = { businessName: 'Acme Sneakers', merchantUrl: 'https://demo.example/shop/acme', vmid: '91234567890' }

function fakeVisa(overrides = {}) {
  const calls = []
  const fn = async (method, path, body) => {
    calls.push({ method, path, body })
    if (overrides[`${method} ${path}`]) return overrides[`${method} ${path}`]
    if (method === 'POST' && path === '/vmrs/v1/merchants') return { status: 201, json: { id: MID, keys: [{ id: KID, isActive: false }] } }
    if (method === 'POST' && path.endsWith('/activate')) return { status: 200, json: { id: KID, isActive: true } }
    return { status: 404, json: { detail: 'not found' } }
  }
  fn.calls = calls
  return fn
}

test('creates the merchant, then activates its key', async () => {
  const visa = fakeVisa()
  const out = await registerMerchantWithVisa({ visa, ...args })
  assert.deepEqual(out, { merchantId: MID, keyId: KID, merchantUrl: args.merchantUrl })
  assert.deepEqual(visa.calls.map((c) => `${c.method} ${c.path}`), ['POST /vmrs/v1/merchants', `POST /vmrs/v1/merchants/${MID}/keys/${KID}/activate`])
})

test('the create request follows Visa\'s merchant schema', async () => {
  const visa = fakeVisa()
  await registerMerchantWithVisa({ visa, ...args })
  const b = visa.calls[0].body
  assert.equal(b.vmid, '91234567890')
  assert.equal(b.indicator, 'TAP')
  assert.equal(b.merchantUrl, args.merchantUrl)
  assert.equal(b.merchantName, 'Acme Sneakers')
  assert.equal(b.paymentPayloadType, 'ENCRYPTED')
  assert.deepEqual(Object.keys(b.encryptionKey).sort(), ['algorithm', 'encryptionKey', 'encryptionType', 'keyName'])
  assert.equal(b.encryptionKey.algorithm, 'RSA-OAEP-256')
  assert.equal(b.encryptionKey.encryptionType, 'A256GCM')
  const key = createPublicKey({ key: Buffer.from(b.encryptionKey.encryptionKey, 'base64'), format: 'der', type: 'spki' })
  assert.equal(key.asymmetricKeyType, 'rsa')
  assert.equal(key.asymmetricKeyDetails.modulusLength, 2048)
})

test('the private key is handed over once, before activation, and never sent to Visa', async () => {
  const visa = fakeVisa()
  let order = []
  let created
  await registerMerchantWithVisa({ visa, ...args, onCreated: async (c) => { created = c; order.push(`stored after ${visa.calls.length} call(s)`) } })
  assert.deepEqual(order, ['stored after 1 call(s)'])
  assert.match(created.privateKeyPem, /^-----BEGIN PRIVATE KEY-----/)
  assert.equal(JSON.stringify(visa.calls).includes('PRIVATE KEY'), false)
})

test('a duplicate merchant URL is reported plainly', async () => {
  const visa = fakeVisa({ 'POST /vmrs/v1/merchants': { status: 409, json: { detail: 'merchantUrl exists' } } })
  await assert.rejects(registerMerchantWithVisa({ visa, ...args }), (e) => e instanceof VisaRegistrationError && /already has a merchant/.test(e.message))
})

test('a rejected registration carries Visa\'s reason', async () => {
  const visa = fakeVisa({ 'POST /vmrs/v1/merchants': { status: 422, json: { detail: [{ msg: 'bad url' }] } } })
  await assert.rejects(registerMerchantWithVisa({ visa, ...args }), (e) => e instanceof VisaRegistrationError && /rejected/.test(e.message))
})

test('an activation failure leaves a retry that only activates', async () => {
  let stored
  const failing = fakeVisa({ [`POST /vmrs/v1/merchants/${MID}/keys/${KID}/activate`]: { status: 500, json: null } })
  await assert.rejects(registerMerchantWithVisa({ visa: failing, ...args, onCreated: async (c) => { stored = c } }), /could not be activated/)
  assert.equal(stored.merchantId, MID)
  const retry = fakeVisa()
  const out = await registerMerchantWithVisa({ visa: retry, ...args, existing: { merchantId: stored.merchantId, keyId: stored.keyId } })
  assert.equal(out.merchantId, MID)
  assert.deepEqual(retry.calls.map((c) => `${c.method} ${c.path}`), [`POST /vmrs/v1/merchants/${MID}/keys/${KID}/activate`])
})

test('a key Visa already activated at creation counts as registered', async () => {
  const visa = fakeVisa({ [`POST /vmrs/v1/merchants/${MID}/keys/${KID}/activate`]: { status: 409, json: { detail: 'This key is already active' } } })
  const out = await registerMerchantWithVisa({ visa, ...args })
  assert.equal(out.merchantId, MID)
})

test('a different 409 on activation is still an error', async () => {
  const visa = fakeVisa({ [`POST /vmrs/v1/merchants/${MID}/keys/${KID}/activate`]: { status: 409, json: { detail: 'key revoked' } } })
  await assert.rejects(registerMerchantWithVisa({ visa, ...args }), /could not be activated: HTTP 409 - key revoked/)
})

test('a response without IDs is an error, not a silent success', async () => {
  const visa = fakeVisa({ 'POST /vmrs/v1/merchants': { status: 201, json: { id: MID, keys: [] } } })
  await assert.rejects(registerMerchantWithVisa({ visa, ...args }), /no merchant or key ID/)
})

test('the Visa record is summarised without the full public key', () => {
  const fullKey = Buffer.alloc(294, 7).toString('base64')
  const out = summarizeVisaMerchant({ id: MID, merchantName: 'Acme', vmid: '9', isActive: true, keys: [{ id: KID, keyName: 'primary', algorithm: 'RSA-OAEP-256', encryptionType: 'A256GCM', expirationDate: '2026-11-27T00:00:00', encryptionKey: fullKey }] })
  assert.equal(out.id, MID)
  assert.equal(out.merchantName, 'Acme')
  assert.equal(out.keys.length, 1)
  assert.match(out.keys[0].fingerprint, /^sha256:[0-9a-f]{24}$/)
  assert.equal(out.keys[0].publicKeyPreview.length, 29)
  assert.equal(JSON.stringify(out).includes(fullKey), false)
  assert.deepEqual(summarizeVisaMerchant({ id: MID }).keys, [])
})
