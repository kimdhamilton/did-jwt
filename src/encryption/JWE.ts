import { fromString } from 'uint8arrays/from-string'
import { base64ToBytes, bytesToBase64url, decodeBase64url, toSealed } from '../util.js'
import type { Decrypter, Encrypter, EncryptionResult, EphemeralKeyPair, JWE, ProtectedHeader } from './types.js'

function validateJWE(jwe: JWE) {
  if (!(jwe.protected && jwe.iv && jwe.ciphertext && jwe.tag)) {
    throw new Error('bad_jwe: missing properties')
  }
  if (jwe.recipients) {
    jwe.recipients.map((rec) => {
      if (!(rec.header && rec.encrypted_key)) {
        throw new Error('bad_jwe: malformed recipients')
      }
    })
  }
}

function encodeJWE({ ciphertext, tag, iv, protectedHeader, recipient }: EncryptionResult, aad?: Uint8Array): JWE {
  const jwe: JWE = {
    protected: <string>protectedHeader,
    iv: bytesToBase64url(iv ?? new Uint8Array(0)),
    ciphertext: bytesToBase64url(ciphertext),
    tag: bytesToBase64url(tag ?? new Uint8Array(0)),
  }
  if (aad) jwe.aad = bytesToBase64url(aad)
  if (recipient) jwe.recipients = [recipient]
  return jwe
}

export async function createJWE(
  cleartext: Uint8Array,
  encrypters: Encrypter[],
  protectedHeader: ProtectedHeader = {},
  aad?: Uint8Array,
  useSingleEphemeralKey = false
): Promise<JWE> {
  if (encrypters[0].alg === 'dir') {
    if (encrypters.length > 1) throw new Error('not_supported: Can only do "dir" encryption to one key.')
    const encryptionResult = await encrypters[0].encrypt(cleartext, protectedHeader, aad)
    return encodeJWE(encryptionResult, aad)
  } else {
    const tmpEnc = encrypters[0].enc
    if (!encrypters.reduce((acc, encrypter) => acc && encrypter.enc === tmpEnc, true)) {
      throw new Error('invalid_argument: Incompatible encrypters passed')
    }
    let cek: Uint8Array | undefined
    let jwe: JWE | undefined
    let epk: EphemeralKeyPair | undefined
    if (useSingleEphemeralKey) {
      epk = encrypters[0].genEpk?.()
      const alg = encrypters[0].alg
      protectedHeader = { ...protectedHeader, alg, epk: epk?.publicKeyJWK }
    }

    for (const encrypter of encrypters) {
      if (!cek) {
        const encryptionResult = await encrypter.encrypt(cleartext, protectedHeader, aad, epk)
        cek = encryptionResult.cek
        jwe = encodeJWE(encryptionResult, aad)
      } else {
        const recipient = await encrypter.encryptCek?.(cek, epk)
        if (recipient) {
          jwe?.recipients?.push(recipient)
        }
      }
    }
    return <JWE>jwe
  }
}

export async function decryptJWE(jwe: JWE, decrypter: Decrypter): Promise<Uint8Array> {
  validateJWE(jwe)
  const protHeader = JSON.parse(decodeBase64url(jwe.protected))
  if (protHeader.enc !== decrypter.enc)
    throw new Error(`not_supported: Decrypter does not supported: '${protHeader.enc}'`)
  const sealed = toSealed(jwe.ciphertext, jwe.tag)
  const aad = fromString(jwe.aad ? `${jwe.protected}.${jwe.aad}` : jwe.protected, 'utf-8')
  let cleartext = null
  if (protHeader.alg === 'dir' && decrypter.alg === 'dir') {
    cleartext = await decrypter.decrypt(sealed, base64ToBytes(jwe.iv), aad)
  } else if (!jwe.recipients || jwe.recipients.length === 0) {
    throw new Error('bad_jwe: missing recipients')
  } else {
    for (let i = 0; !cleartext && i < jwe.recipients.length; i++) {
      const recipient = jwe.recipients[i]
      Object.assign(recipient.header, protHeader)
      if (recipient.header.alg === decrypter.alg) {
        cleartext = await decrypter.decrypt(sealed, base64ToBytes(jwe.iv), aad, recipient)
      }
    }
  }
  if (cleartext === null) throw new Error('failure: Failed to decrypt')
  return cleartext
}
