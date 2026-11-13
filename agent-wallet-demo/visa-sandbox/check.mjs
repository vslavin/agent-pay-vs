import { createHmac } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'

// Connectivity check for Visa's sandbox using X-Pay Token (API key + shared secret).
// Reads credentials/visa.json (git-ignored). Prints only Visa's status and message.

const FILE = new URL('./credentials/visa.json', import.meta.url)
if (!existsSync(FILE)) {
  console.error('Missing credentials/visa.json. Copy visa.example.json there and fill in your API key and shared secret.')
  process.exit(1)
}
const { apiKey, sharedSecret } = JSON.parse(readFileSync(FILE, 'utf8'))
if (!apiKey || !sharedSecret || /PASTE_/.test(apiKey + sharedSecret)) {
  console.error('credentials/visa.json still has placeholder values.')
  process.exit(1)
}

const BASE = 'https://sandbox.api.visa.com'
const PATH = '/v1/trustedAgentProtocol'
// Visa's X-Pay Token signs "<timestamp><resource path><query string><body>". The resource path convention
// varies by API, so try the likely forms and report which one (if any) is accepted.
const RESOURCE_PATHS = ['/trustedAgentProtocol', 'trustedAgentProtocol', '/v1/trustedAgentProtocol', 'v1/trustedAgentProtocol']

for (const resourcePath of RESOURCE_PATHS) {
  const query = `apikey=${apiKey}`
  const ts = String(Math.floor(Date.now() / 1000))
  const token = `xv2:${ts}:${createHmac('sha256', sharedSecret).update(ts + resourcePath + query).digest('hex')}`
  const res = await fetch(`${BASE}${PATH}?${query}`, { headers: { 'X-PAY-TOKEN': token, Accept: 'application/json' } })
  const text = await res.text()
  let msg = text.slice(0, 160)
  try { const j = JSON.parse(text); msg = j.responseStatus ? `${j.responseStatus.code} ${j.responseStatus.message}` : JSON.stringify(j).slice(0, 160) } catch {}
  console.log(`resource path "${resourcePath}" -> HTTP ${res.status}  ${msg}  (correlation ${res.headers.get('x-correlation-id') ?? 'n/a'})`)
  if (res.ok) break
}
