import { readFileSync } from 'node:fs'
import { createVisaClient } from './client.mjs'

// Visa sandbox client with credentials from credentials/visa.json (git-ignored).
// VISA_BASE_URL overrides the server, for tests against a local fake.
const { apiKey, sharedSecret } = JSON.parse(readFileSync(new URL('./credentials/visa.json', import.meta.url), 'utf8'))
export const visa = createVisaClient({ apiKey, sharedSecret, base: process.env.VISA_BASE_URL || undefined })
export { resourcePathOf } from './client.mjs'
