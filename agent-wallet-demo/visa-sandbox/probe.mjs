import { visa } from './visa.mjs'
const brief = (r) => `HTTP ${r.status}  ${r.json?.responseStatus ? `${r.json.responseStatus.code} ${r.json.responseStatus.message}` : r.json?.detail ?? r.text.slice(0, 120)}`
console.log('GET /v1/trustedAgentProtocol            ->', brief(await visa('GET', '/v1/trustedAgentProtocol')))
console.log('GET /vmrs/v1/merchants/<unknown uuid>    ->', brief(await visa('GET', '/vmrs/v1/merchants/00000000-0000-4000-8000-000000000000')))
console.log('GET /vmrs/v1/merchants/<unknown>/keys    ->', brief(await visa('GET', '/vmrs/v1/merchants/00000000-0000-4000-8000-000000000000/keys')))
