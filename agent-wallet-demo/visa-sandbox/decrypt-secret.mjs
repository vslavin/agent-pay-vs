import { constants, createPrivateKey, privateDecrypt } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Decrypts the shared secret Visa shows under Credentials > X-Pay Token > Inbound.
// Reads credentials/xpay/shared-secret.enc (base64) and credentials/xpay/private.pem, then stores the
// result in credentials/visa.json. The secret is never printed.

const dir = new URL('./credentials/', import.meta.url)
const encFile = new URL('./xpay/shared-secret.enc', dir)
const keyFile = new URL('./xpay/private.pem', dir)
const cfgFile = new URL('./visa.json', dir)
for (const f of [encFile, keyFile, cfgFile]) {
  if (!existsSync(f)) { console.error(`Missing ${f.pathname.split('/credentials/')[1]}`); process.exit(1) }
}

const cipher = Buffer.from(readFileSync(encFile, 'utf8').replace(/\s+/g, ''), 'base64')
const plausible = (buf) => buf.length >= 8 && buf.length <= 128 && /^[\x21-\x7e]+$/.test(buf.toString('latin1'))
console.log(`encrypted value: ${cipher.length} bytes (a 2048-bit RSA key produces 256)`)

const attempts = []
attempts.push(['node RSA-OAEP, SHA-256', () => privateDecrypt({ key: createPrivateKey(readFileSync(keyFile)), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cipher)])
for (const [label, extra] of [['openssl OAEP SHA-256, default MGF1', []], ['openssl OAEP SHA-256, MGF1 SHA-256', ['-pkeyopt', 'rsa_mgf1_md:sha256']], ['openssl OAEP SHA-256, MGF1 SHA-1', ['-pkeyopt', 'rsa_mgf1_md:sha1']]]) {
  attempts.push([label, () => {
    const tmp = mkdtempSync(join(tmpdir(), 'xpay-'))
    try {
      writeFileSync(join(tmp, 'in.bin'), cipher)
      return execFileSync('openssl', ['pkeyutl', '-decrypt', '-in', join(tmp, 'in.bin'), '-inkey', keyFile.pathname,
        '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', ...extra], { stdio: ['ignore', 'pipe', 'ignore'] })
    } finally { rmSync(tmp, { recursive: true, force: true }) }
  }])
}

for (const [label, run] of attempts) {
  try {
    const plain = run()
    if (plausible(plain)) {
      const cfg = JSON.parse(readFileSync(cfgFile, 'utf8'))
      cfg.sharedSecret = plain.toString('latin1')
      writeFileSync(cfgFile, JSON.stringify(cfg, null, 2))
      chmodSync(cfgFile, 0o600)
      console.log(`decrypted with: ${label}; saved to credentials/visa.json (${plain.length} characters, not shown)`)
      process.exit(0)
    }
    console.log(`${label}: decrypted but the result doesn't look like a secret`)
  } catch (e) {
    console.log(`${label}: failed`)
  }
}
console.error('Could not decrypt. Most likely the public key uploaded to Visa is not the one matching credentials/xpay/private.pem.')
process.exit(1)
