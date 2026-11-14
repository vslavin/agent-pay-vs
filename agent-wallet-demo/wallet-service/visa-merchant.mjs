import { createHash, generateKeyPairSync } from 'node:crypto'

// Visa's docs call `vmid` optional, but the sandbox rejects a registration without it ("body.vmid: Field required").
// A real merchant has a VMID from its acquirer; for demo merchants we derive a stable 11-digit placeholder from a
// seed (the merchant's Keycloak ID), starting with 9 so it is recognisably synthetic.
export function sandboxVmid(seed) {
  const n = BigInt('0x' + createHash('sha256').update(String(seed)).digest('hex').slice(0, 12)) % 10n ** 10n
  return '9' + n.toString().padStart(10, '0')
}

// Registers a merchant in Visa's Merchant Registry Service (VMRS): create the merchant with a freshly
// generated RSA encryption key, then activate the key (Visa creates new keys deactivated).
// `visa(method, path, body)` is injected so this can be tested without calling Visa.

export class VisaRegistrationError extends Error {}

// Visa answers with a string, a list of validation errors ({loc, msg, type}) or a responseStatus object.
export function detail(r) {
  const d = r.json?.detail ?? r.json?.responseStatus ?? null
  let text
  if (d == null) text = r.text ? String(r.text).slice(0, 200) : ''
  else if (typeof d === 'string') text = d
  else if (Array.isArray(d)) text = d.map((e) => (typeof e === 'string' ? e : `${(e.loc ?? []).join('.')}: ${e.msg ?? JSON.stringify(e)}`)).join('; ')
  else text = d.message ? `${d.code ? `${d.code} ` : ''}${d.message}` : JSON.stringify(d)
  return `HTTP ${r.status}${text ? ` - ${text}` : ''}`.slice(0, 400)
}

// existing: { merchantId, keyId } from an earlier attempt that created the merchant but failed to activate.
// onCreated({ merchantId, keyId, privateKeyPem }) runs as soon as Visa has the merchant, so the caller can
// persist the private key before the activation call.
export async function registerMerchantWithVisa({ visa, businessName, merchantUrl, vmid, existing = null, onCreated = async () => {} }) {
  let { merchantId, keyId } = existing ?? {}
  if (!merchantId) {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const created = await visa('POST', '/vmrs/v1/merchants', {
      vmid,
      indicator: 'TAP',
      merchantUrl,
      merchantName: businessName,
      paymentPayloadType: 'ENCRYPTED',
      encryptionKey: {
        keyName: 'primary',
        algorithm: 'RSA-OAEP-256',
        encryptionType: 'A256GCM',
        encryptionKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      },
    })
    if (created.status === 409) {
      const d = detail(created)
      // Visa's sandbox allows one merchant per domain, so every store served from the same domain after the first is refused.
      throw new VisaRegistrationError(/domain/i.test(d)
        ? `Visa allows only one merchant per domain, and ${new URL(merchantUrl).host} is already registered (${d}). Another store needs its own domain to be registered. A store works without being registered.`
        : `Visa says this merchant already exists (${d}). It does not say whether the URL, the Visa Merchant ID or the name clashed, and it offers no way to list or delete merchants.`)
    }
    if (created.status !== 201) throw new VisaRegistrationError(`Visa rejected the registration: ${detail(created)}`)
    merchantId = created.json?.id
    keyId = created.json?.keys?.[0]?.id
    if (!merchantId || !keyId) throw new VisaRegistrationError('Visa accepted the registration but returned no merchant or key ID.')
    await onCreated({ merchantId, keyId, privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) })
  }
  const activated = await visa('POST', `/vmrs/v1/merchants/${merchantId}/keys/${keyId}/activate`)
  // Visa's docs say new keys start deactivated and that activating twice is fine, but in the sandbox the key is
  // already active after creation and a second activation returns 409 "This key is already active".
  const alreadyActive = activated.status === 409 && /already active/i.test(detail(activated))
  if (activated.status !== 200 && !alreadyActive) throw new VisaRegistrationError(`The merchant was created but its key could not be activated: ${detail(activated)}`)
  return { merchantId, keyId, merchantUrl }
}

// Shapes Visa's merchant record for display: keeps Visa's fields, replaces each key's full public key with a
// fingerprint and a short preview so the page and JSON stay readable.
export function summarizeVisaMerchant(m) {
  const keys = (m.keys ?? []).map((k) => {
    const der = k.encryptionKey ? Buffer.from(String(k.encryptionKey), 'base64') : null
    return {
      id: k.id, keyName: k.keyName, algorithm: k.algorithm, encryptionType: k.encryptionType,
      createdAt: k.createdAt, updatedAt: k.updatedAt, expirationDate: k.expirationDate,
      fingerprint: der ? `sha256:${createHash('sha256').update(der).digest('hex').slice(0, 24)}` : null,
      publicKeyPreview: k.encryptionKey ? `${String(k.encryptionKey).slice(0, 28)}…` : null,
    }
  })
  const { keys: _omitted, ...rest } = m
  return { ...rest, keys }
}
