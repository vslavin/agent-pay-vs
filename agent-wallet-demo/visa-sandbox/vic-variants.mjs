import https from 'node:https'
import tls from 'node:tls'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'

// Tries the empty Intelligent Commerce request with different credential combinations, to learn which one Visa
// wants. Nothing is created. Prints only Visa's status and message.
const dir = new URL('./credentials/twoway/', import.meta.url)
const { apiKey, sharedSecret } = JSON.parse(readFileSync(new URL('./credentials/visa.json', import.meta.url), 'utf8'))
const b = JSON.parse(readFileSync(new URL('basic.json', dir), 'utf8'))
const basic = 'Basic ' + Buffer.from(`${b.userId}:${b.password}`).toString('base64')
const read = (f) => readFileSync(new URL(f, dir), 'utf8')
const agent = new https.Agent({ cert: [read('client.pem'), read('ca-issuing.pem')].join('\n'), key: read('private.pem'), ca: [...tls.rootCertificates, read('ca-root.pem'), read('ca-issuing.pem')] })

const PATH = '/vacp/v2/credentials-for-instruction'
const body = '{}'
function send(query, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request({ host: 'sandbox.api.visa.com', path: PATH + (query ? `?${query}` : ''), method: 'POST', agent,
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers } }, (res) => {
      let t = ''; res.on('data', (c) => (t += c)); res.on('end', () => { let j = null; try { j = JSON.parse(t) } catch {}
        const m = j?.responseStatus ? `${j.responseStatus.code} ${j.responseStatus.message}` : (j ? JSON.stringify(j).slice(0, 260) : t.slice(0, 200)); resolve(`HTTP ${res.statusCode}  ${m}`) })
    })
    req.on('error', reject); req.write(body); req.end()
  })
}
const xpay = (query) => { const ts = String(Math.floor(Date.now() / 1000)); return `xv2:${ts}:${createHmac('sha256', sharedSecret).update(ts + 'v2/credentials-for-instruction' + query + body).digest('hex')}` }
const variants = [
  ['certificate + Basic                         ', '', { Authorization: basic }],
  ['certificate + Basic + apikey                ', `apikey=${apiKey}`, { Authorization: basic }],
  ['certificate + apikey (no Basic)             ', `apikey=${apiKey}`, {}],
  ['certificate + apikey + X-Pay-Token          ', `apikey=${apiKey}`, { 'X-PAY-TOKEN': xpay(`apikey=${apiKey}`) }],
  ['certificate + Basic + apikey + X-Pay-Token  ', `apikey=${apiKey}`, { Authorization: basic, 'X-PAY-TOKEN': xpay(`apikey=${apiKey}`) }],
]
for (const [label, q, h] of variants) {
  try { console.log(`${label} -> ${await send(q, h)}`) } catch (e) { console.log(`${label} -> ${e.code ?? ''} ${e.message}`) }
}
