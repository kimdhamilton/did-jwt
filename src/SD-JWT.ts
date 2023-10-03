import { randomBytes } from '@noble/hashes/utils'
import { bytesToBase64url, decodeBase64url, stringToBytes } from './util.js'
import { sha256 } from '@noble/hashes/sha256'
import {
  JWTDecoded,
  JWTHeader,
  JWTOptions,
  JWTPayload,
  JWTVerified,
  JWTVerifyOptions,
  createJWT,
  decodeJWT,
} from './JWT.js'

const MINIMUM_SALT_LENGTH = 16
const DEFAULT_SD_ALG = 'sha-256'

export interface SdJWTPayload extends JWTPayload {
  _sd_alg: string
  _sd?: string[]
}
export interface SdJWTOptions extends JWTOptions {
  disclosures: string[]
  kb_jwt?: string
}

export interface SdJWTDecoded extends JWTDecoded {
  payload: JWTPayload
  kb_jwt?: string
}

export interface SdJWTVerified extends JWTVerified {
  payload: Partial<SdJWTPayload>
}

interface SplitSdJWT {
  jwt: string
  disclosures: string[]
  kbJwt?: string
}

export interface CreateDisclosureOptions {
  salt?: string
  specCompatStringify?: boolean
}

/* Internal types */

// Used to ensure that the value is a JSON type; see 5.2.1 SD-JWT
type JSONPrimitive = string | number | boolean | null
type JSONObject = { [key: string]: JSONValue }
type JSONArray = JSONValue[]
type JSONValue = JSONPrimitive | JSONObject | JSONArray

interface Disclosure {
  salt: string
  value: JSONValue
}

interface ArrayElementDisclosure extends Disclosure {}

interface ObjectPropertyDisclosure extends Disclosure {
  key: string
}

/**
 *
 *
 * @export
 * @param {Partial<SdJWTPayload>} payload
 * @param {SdJWTOptions} { issuer, signer, alg, expiresIn, canonicalize, disclosures, kb_jwt }
 * @param {Partial<JWTHeader>} [header={}]
 * @return {*}  {Promise<string>}
 */
export async function createSdJWT(
  payload: Partial<SdJWTPayload>,
  { issuer, signer, alg, expiresIn, canonicalize, disclosures, kb_jwt }: SdJWTOptions,
  header: Partial<JWTHeader> = {}
): Promise<string> {
  const jwt = await createJWT(payload, { issuer, signer, alg, expiresIn, canonicalize }, header)
  return formSdJwt(jwt, disclosures, kb_jwt)
}

/**
 *  Decodes an SD-JWT and returns an object representing the payload
 *
 * This performs the following checks required by 6.1.2-7:
 * - Ensure  nbf, iat, and exp clains, if present, are not selectively disclosed
 * - Ensure the _sd_alg header parameter is supported
 * - Ensure the disclosures are well-formed:
 *     - Object property disclosures are arrays of length 3
 *     - Array disclosures are arrays of length 2
 * - Claim names do not exist more than once (i.e. a disclosure does not overwrite a clear text claim)
 * - Digests are not found more than once (TODO)
 *
 * Per 6.1.6 and 7, this removes _sd and _sd_alg are removed from the payload
 *
 *  @example
 *  decodeSdJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1...~<Disclosure 1>~...<optional KB-JWT>')
 *
 * @export
 * @param {string} sdJwt                an SD-JWT to verify
 * @param {boolean} [recurse=true]      whether to recurse into the payload to decode any nested SD-JWTs
 * @return {*}  {JWTDecoded}            the decoded SD-JWT
 */
export function decodeSdJWT(sdJwt: string, recurse: boolean = true): SdJWTDecoded {
  const { jwt, disclosures, kbJwt } = splitSdJwt(sdJwt)

  const decodedJwt = decodeJWT(jwt, recurse)

  const sdAlg = decodedJwt.payload._sd_alg || DEFAULT_SD_ALG
  const disclosureMap = buildDigestDisclosureMap(disclosures, sdAlg)
  const converted = expandDisclosures(decodedJwt.payload, disclosureMap, recurse) as JWTPayload

  const decodedSdJwt: SdJWTDecoded = {
    ...decodedJwt,
    payload: {
      ...converted,
    },
  }

  if (kbJwt) {
    decodedSdJwt.kb_jwt = kbJwt
  }

  return decodedSdJwt
}
/**
 *
 * Verify an SD-JWT and return the payload, performing SD-JWT-specific checks via decodeSdJWT
 *
 * @export
 * @param {string} sdJwt
 * @param {JWTVerifyOptions} [options={
 *     resolver: undefined,
 *     auth: undefined,
 *     audience: undefined,
 *     callbackUrl: undefined,
 *     skewTime: undefined,
 *     proofPurpose: undefined,
 *     policies: {},
 *     didAuthenticator: undefined,
 *   }]
 * @return {*}  {Promise<JWTVerified>}
 */
export async function verifyJWT(
  sdJwt: string,
  options: JWTVerifyOptions = {
    resolver: undefined,
    auth: undefined,
    audience: undefined,
    callbackUrl: undefined,
    skewTime: undefined,
    proofPurpose: undefined,
    policies: {},
    didAuthenticator: undefined,
  }
): Promise<SdJWTVerified> {
  const { jwt } = splitSdJwt(sdJwt)
  const verified = await verifyJWT(jwt, options)
  const decoded = decodeSdJWT(sdJwt, false)
  verified.payload = decoded.payload
  return verified
}

/* Optional helper methpds for building SD-JWTs */

/**
 * Make a payload selectively disclosable, as described in 5.2. Selective Disclosure.
 *
 * Returns an object with the SD-JWT payload and an array of disclosures, which can be used
 *
 * @export
 * @param {Partial<JWTPayload>} clearText the payload to be selectively disclosed, in clear text
 * @param {string} [sd_alg=DEFAULT_SD_ALG]
 * @return {*}  {SdSplit}   consisting of the SD-JWT payload and an array of disclosures
 */

export function makeSelectivelyDisclosable(
  clearText: Partial<JWTPayload>,
  sd_alg: string = DEFAULT_SD_ALG
): Map<string, string> {
  const disclosures = Object.entries(clearText).map(([key, value]) => {
    return createObjectPropertyDisclosure(key, value)
  })

  const disclosureMap = buildDigestDisclosureMap(disclosures, sd_alg)

  return disclosureMap
}

/**
 *  Creates the serialized SD-JWT with disclosures, which looks like the following:
 *  <JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>
 *
 * This format is used when issuers send an SD-JWT to a holder, and when a holder
 * sends an SD=JWT to a verifier, with the important distinction that the holder may choose to
 * reveal a subset of the disclosures provided by the issuer.
 *
 * @export
 * @param {string} jwt
 * @param {string[]} disclosures
 * @param {string} [kbJwt]
 * @return {*}  {string}
 */
export function formSdJwt(jwt: string, encodedDisclosures: string[], kbJwt?: string): string {
  return `${jwt}~${encodedDisclosures.join('~')}~${kbJwt ? kbJwt : ''}`
}

/* Utilites for SD-JWT Creation */

export function createSalt(length = MINIMUM_SALT_LENGTH): string {
  return bytesToBase64url(randomBytes(length))
}

/**
 * Create an object property disclosure as described in SD-JWT spec 5.2.1. Disclosures for Object Properties.
 *
 * Optionally pass in a salt, which is useful for testing against SD-JWT test vectors. Otherwise one will be generated.
 *
 * @export
 * @param {string} key
 * @param {JSONValue} value
 * @param {CreateDisclosureOptions} [options]
 * @return {*}  {string}        base64url-encoded disclosure
 */
export function createObjectPropertyDisclosure(
  key: string,
  value: JSONValue,
  options?: CreateDisclosureOptions
): string {
  const salt = options?.salt || createSalt()
  const specStringify = options?.specCompatStringify || false
  const disclosure: ObjectPropertyDisclosure = { salt: salt, key: key, value: value }
  return encodeDisclosure(disclosure, specStringify)
}

/**
 * Create an array element disclosure as described in SD-JWT spec 5.2.2. Disclosures for Array Elements.
 *
 * Optionally pass in a salt, which is useful for testing against SD-JWT test vectors. Otherwise one will be generated.
 *
 * @export
 * @param {JSONValue} arrayElement
 * @param {CreateDisclosureOptions} [options]
 * @return {*}  {string}        base64url-encoded disclosure
 */
export function createArrayElementDisclosure(arrayElement: JSONValue, options?: CreateDisclosureOptions): string {
  const salt = options?.salt || createSalt()
  const specStringify = options?.specCompatStringify || false
  const disclosure: ArrayElementDisclosure = { salt: salt, value: arrayElement }
  return encodeDisclosure(disclosure, specStringify)
}

/**
 * Encode an SD-JWT spec 5.2.1. Disclosures for Object Properties. Optional specCompatStringify
 * argument allows demonstration of compatibility with the SD-JWT spec examples.
 *
 * @param {Disclosure} disclosure
 * @param {boolean} [specCompatStringify=false]
 * @return {string}
 */
function encodeDisclosure(disclosure: Disclosure, specCompatStringify: boolean = false): string {
  const disclosureAsArray = disclosureToArray(disclosure)
  let stringified: string
  if (specCompatStringify) {
    stringified = doSpecStringify(disclosureAsArray)
  } else {
    stringified = JSON.stringify(disclosureAsArray)
  }
  const asBytes = stringToBytes(stringified)
  return bytesToBase64url(asBytes)
}

/**
 * Convert disclosure object to an array of strings and JSONValues
 *
 * @param {Disclosure} disclosure
 * @return {*}  {JSONValue[]}
 */
function disclosureToArray(disclosure: Disclosure): JSONValue[] {
  if (Object.prototype.hasOwnProperty.call(disclosure, 'key')) {
    const objectPropertyDisclosure = disclosure as ObjectPropertyDisclosure
    return [disclosure.salt, objectPropertyDisclosure.key, disclosure.value]
  } else {
    return [disclosure.salt, disclosure.value]
  }
}

/**
 * JSON.stringify workaround for arrays, in order to match SD-JWT spec.
 *
 * Stringify element-wise and join with commas, space-separated.
 *
 * @param {Disclosure} disclosure
 * @return {*}  {string}
 */
function doSpecStringify(disclosure: JSONValue[]): string {
  const elements = disclosure.map((element) => {
    return JSON.stringify(element)
  })

  return `[${elements.join(', ')}]`
}

/**
 * Hash a disclosure using the specified hash algorithm.
 *
 * @export
 * @param {string} disclosure           base64url-encoded disclosure TODO: add regex to test
 * @param {string} [sd_alg=DEFAULT_SD_ALG]     hash algorithm to use for disclosures
 * @return {*}  {string}                hashed disclosure
 */
export function hashDisclosure(disclosure: string, sd_alg: string = DEFAULT_SD_ALG): string {
  if (sd_alg === DEFAULT_SD_ALG) {
    const digest = sha256.create().update(stringToBytes(disclosure)).digest()
    return bytesToBase64url(digest)
  }
  throw new Error(`Unsupported sd_alg: ${sd_alg}`)
}

function _splitSdJwt(sdJwt: string): string[] {
  return sdJwt.split('~')
}

function splitSdJwt(sdJwt: string): SplitSdJWT {
  const parts = _splitSdJwt(sdJwt)
  const kbJwt = parts.pop() || ''
  const [jwt, ...disclosures] = parts
  return { jwt, disclosures, kbJwt }
}

/* Utilities for SD-JWT decoding */

/**
 * Compute disclosure digests so we can perform lookup from payload
 * @param {string[]} disclosures
 * @param {string} [sd_alg=DEFAULT_SD_ALG]
 * @return {*}  {Map<string, string>}
 */
function buildDigestDisclosureMap(disclosures: string[], sd_alg: string = DEFAULT_SD_ALG): Map<string, string> {
  const disclosureHashEntries = disclosures.map((disclosure) => {
    const digest = hashDisclosure(disclosure, sd_alg)
    return { disclosure, digest }
  })
  return new Map(disclosureHashEntries.map((obj) => [obj.digest, obj.disclosure]))
}

/**
 *
 *
 * @param {any[]} arrayElements
 * @param {Map<string, string>} disclosureMap
 * @param {boolean} recurse
 * @return {*}  {any[]}
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function expandArrayElements(arrayElements: any[], disclosureMap: Map<string, string>, recurse: boolean): any[] {
  const mappedArray = []
  for (const element of arrayElements) {
    if (typeof element === 'object') {
      if ('...' in element) {
        const disclosure = disclosureMap.get(element['...'])
        // skip if not revealed in disclosures
        if (!disclosure) {
          continue
        }
        const parsed = parseArrayElementDisclosure(disclosure)
        mappedArray.push(parsed.value)
      } else {
        // else recurse into object if recurse is true; if not, just add the
        // object back to the array
        let el = element
        if (recurse) {
          el = expandDisclosures(element, disclosureMap, recurse)
        }
        mappedArray.push(el)
      }
    } else {
      // else its a primitive; add it to the array
      mappedArray.push(element)
    }
  }
  return mappedArray
}

/**
 * Search for disclosure digests in the payload and replace with the parsed disclosures,
 * with optional recursion into the payload, as described in 6.1.3.
 *
 * To avoid duplicate recursive processing, this expands the disclosures and deletes the
 * digests, per 6.1 Verification
 * @export
 * @param {object} jwtPayload
 * @param {Map<string, string>} disclosureMap
 * @param {boolean} [recurse=true]
 * @return {*}  {object}
 */
export function expandDisclosures(
  jwtPayload: object,
  disclosureMap: Map<string, string>,
  recurse: boolean = true
): object {
  // clone the input
  const wip = JSON.parse(JSON.stringify(jwtPayload))

  const entries = Object.entries(jwtPayload)

  for (const [key, value] of entries) {
    if (key === '_sd') {
      const sdValues = value as string[]
      const asObjectDisclosures: ObjectPropertyDisclosure[] = sdValues
        .filter((digest: string) => disclosureMap.has(digest))
        .map((digest: string) => {
          const disclosure = disclosureMap.get(digest) as string
          const parsed = parseObjectPropertyDisclosure(disclosure)
          if (!isValidDisclosureKey(parsed.key)) {
            throw new Error(`Invalid disclosure key: ${parsed.key}`)
          }
          return parsed
        })
      asObjectDisclosures.forEach((d) => {
        if (d.key in wip) {
          throw new Error(`Duplicate key: ${d}`)
        } else {
          let value = d.value
          if (recurse) {
            if (Array.isArray(value)) {
              value = expandArrayElements(value, disclosureMap, recurse)
            } else if (typeof value === 'object' && value !== null) {
              value = expandDisclosures(value, disclosureMap, recurse) as JSONValue
            }
          }
          wip[d.key] = value
          // TODO: here and elsewhere -- object.assign?
        }
      })

      delete wip['_sd']
    } else if (Array.isArray(value)) {
      const mapped = expandArrayElements(value, disclosureMap, recurse)
      wip[key] = mapped
    } else if (recurse && typeof value === 'object') {
      const mapped = expandDisclosures(value, disclosureMap, recurse)
      wip[key] = mapped
    }
  }
  return wip
}

function isValidDisclosureKey(key: string): boolean {
  return !(key in ['nbf', 'iat', 'exp'])
}

export function parseArrayElementDisclosure(encodedDisclosure: string): ArrayElementDisclosure {
  const decoded = decodeBase64url(encodedDisclosure)
  const parsed = JSON.parse(decoded)

  if (!Array.isArray(parsed)) {
    throw new Error(`Invalid disclosure format: ${parsed}`)
  }

  const disclosureArray = parsed as JSONValue[]

  const disclosure: ArrayElementDisclosure = {
    salt: disclosureArray[0] as string,
    value: disclosureArray[1] as JSONValue,
  }
  return disclosure
}

export function parseObjectPropertyDisclosure(encodedDisclosure: string): ObjectPropertyDisclosure {
  const decoded = decodeBase64url(encodedDisclosure)
  const parsed = JSON.parse(decoded)

  if (!Array.isArray(parsed)) {
    throw new Error(`Invalid disclosure format: ${parsed}`)
  }

  const disclosureArray = parsed as JSONValue[]

  if (disclosureArray.length !== 3) {
    throw new Error(`Disclosure array length is not supported`)
  }

  return {
    salt: disclosureArray[0] as string,
    key: disclosureArray[1] as string,
    value: disclosureArray[2] as JSONValue,
  }
}
