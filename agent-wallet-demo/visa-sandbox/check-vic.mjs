import https from 'node:https'
import tls from 'node:tls'
import { existsSync, readFileSync } from 'node:fs'

// Connectivity check for Visa Intelligent Commerce over mutual TLS (Two-Way SSL).
// Sends an EMPTY request to the credentials-for-instruction endpoint: nothing is created. If the client
// certificate is accepted, Visa answers with a validation error about the missing fields; if not, with an
// authentication error. Reads credentials/twoway/{client.pem,private.pem} and, for the HTTP Basic part of
// Visa's Two-Way SSL, credentials/twoway/basic.json with {"userId", "password"} (all git-ignored).

const dir = new URL('./credentials/twoway/', import.meta.url)
const need = ['client.pem', 'private.pem']
const missing = need.filter((f) => !existsSync(new URL(f, dir)))
if (missing.length) { console.error(`Missing credentials/twoway/${missing.join(', credentials/twoway/')}`); process.exit(1) }

const visaCas = ['ca-root.pem', 'ca-issuing.pem'].filter((f) => existsSync(new URL(f, dir))).map((f) => readFileSync(new URL(f, dir), 'utf8'))
// Trust the normal public CAs plus Visa's, and send the issuing CA along with the client certificate.
const issuing = existsSync(new URL('ca-issuing.pem', dir)) ? [readFileSync(new URL('ca-issuing.pem', dir), 'utf8')] : []
const agent = new https.Agent({
  cert: [readFileSync(new URL('client.pem', dir), 'utf8'), ...issuing].join('\n'), // one PEM string = a chain
  key: readFileSync(new URL('private.pem', dir)),
  ca: [...tls.rootCertificates, ...visaCas],
})

const basicFile = new URL('basic.json', dir)
let basic = null
if (existsSync(basicFile)) {
  const { userId, password } = JSON.parse(readFileSync(basicFile, 'utf8'))
  if (!userId || !password || /PASTE_/.test(userId + password)) { console.error('credentials/twoway/basic.json still has placeholder values.'); process.exit(1) }
  basic = 'Basic ' + Buffer.from(`${userId}:${password}`).toString('base64')
} else {
  console.log('(no credentials/twoway/basic.json: sending the certificate only)')
}

function call(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body)
    const req = https.request({ host: 'sandbox.api.visa.com', path, method, agent,
      headers: { Accept: 'application/json', ...(basic ? { Authorization: basic } : {}), ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) } }, (res) => {
      let text = ''
      res.on('data', (c) => (text += c))
      res.on('end', () => { let json = null; try { json = JSON.parse(text) } catch {} resolve({ status: res.statusCode, json, text, correlation: res.headers['x-correlation-id'] }) })
    })
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

const brief = (r) => r.json?.responseStatus ? `${r.json.responseStatus.code} ${r.json.responseStatus.message}` : (r.json ? JSON.stringify(r.json).slice(0, 240) : r.text.slice(0, 240))
const probes = [
  ['GET', '/vdp/helloworld', undefined, "Visa's Hello World (works for any project once Two-Way SSL is right)"],
  ['POST', '/vacp/v2/credentials-for-instruction', {}, 'Intelligent Commerce, empty body (creates nothing)'],
]
for (const [method, path, body, label] of probes) {
  try {
    const r = await call(method, path, body)
    console.log(`${method} ${path} -> HTTP ${r.status}  ${brief(r)}\n    (${label}; correlation ${r.correlation ?? 'n/a'})`)
  } catch (e) {
    console.log(`${method} ${path} -> TLS or network error: ${e.code ?? ''} ${e.message}`)
  }
}
