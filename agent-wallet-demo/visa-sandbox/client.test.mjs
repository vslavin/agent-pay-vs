import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createHmac } from 'node:crypto'
import { createVisaClient, resourcePathOf } from './client.mjs'

const secret = 'test-shared-secret'
const apiKey = 'TESTKEY123'

function fakeVisa() {
  const seen = []
  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      const url = new URL(req.url, 'http://x')
      const [, ts, hash] = (req.headers['x-pay-token'] ?? '').split(':')
      const expected = createHmac('sha256', secret).update(ts + resourcePathOf(url.pathname) + url.search.slice(1) + body).digest('hex')
      seen.push({ method: req.method, path: url.pathname, body, valid: hash === expected && url.searchParams.get('apikey') === apiKey })
      res.writeHead(seen.at(-1).valid ? 200 : 401, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: seen.at(-1).valid }))
    })
  })
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, base: `http://127.0.0.1:${server.address().port}` })))
}

test('resource path drops the leading slash and the first segment', () => {
  assert.equal(resourcePathOf('/v1/trustedAgentProtocol'), 'trustedAgentProtocol')
  assert.equal(resourcePathOf('/vmrs/v1/merchants/abc/keys/def/activate'), 'v1/merchants/abc/keys/def/activate')
})

test('GET, POST with a body and POST without a body all carry a valid X-Pay token', async () => {
  const f = await fakeVisa()
  try {
    const visa = createVisaClient({ apiKey, sharedSecret: secret, base: f.base })
    assert.equal((await visa('GET', '/vmrs/v1/merchants/abc')).status, 200)
    assert.equal((await visa('POST', '/vmrs/v1/merchants', { merchantName: 'Café ☕', indicator: 'TAP' })).status, 200)
    assert.equal((await visa('POST', '/vmrs/v1/merchants/abc/keys/def/activate')).status, 200)
    assert.deepEqual(f.seen.map((s) => s.valid), [true, true, true])
    assert.equal(JSON.parse(f.seen[1].body).merchantName, 'Café ☕')
  } finally { f.server.close() }
})

test('a wrong secret is rejected', async () => {
  const f = await fakeVisa()
  try {
    const visa = createVisaClient({ apiKey, sharedSecret: 'wrong', base: f.base })
    assert.equal((await visa('GET', '/vmrs/v1/merchants/abc')).status, 401)
  } finally { f.server.close() }
})
