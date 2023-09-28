import { randomBytes } from '@noble/hashes/utils'
import { bytesToBase64url, decodeBase64url, stringToBytes } from './util.js'
import { sha256 } from '@noble/hashes/sha256'
import { JWTDecoded, JWTHeader, JWTOptions, JWTPayload, createJWT, decodeJWT } from './JWT.js'

const MINIMUM_SALT_LENGTH = 16
const DISCLOSURE_SEPARATOR = '~'
const DEFAULT_SD_ALG = 'sha-256'

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

interface SdJWTPayload extends JWTPayload {
  _sd_alg: string
  _sd?: string[]
}

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
 * @param {string} [salt]
 * @return {*}  {string}        base64url-encoded disclosure
 */
export function createObjectPropertyDisclosure(key: string, value: JSONValue, salt?: string): string {
  salt = salt || createSalt()
  const disclosure: ObjectPropertyDisclosure = { salt: salt, key: key, value: value }
  return encodeDisclosure(disclosure)
}

/**
 * Create an array element disclosure as described in SD-JWT spec 5.2.2. Disclosures for Array Elements.
 *
 * Optionally pass in a salt, which is useful for testing against SD-JWT test vectors. Otherwise one will be generated.
 *
 * @export
 * @param {JSONValue} arrayElement
 * @param {string} [salt]
 * @return {*}  {string}        base64url-encoded disclosure
 */
export function createArrayElementDisclosure(arrayElement: JSONValue, salt?: string): string {
  salt = salt || createSalt()
  const disclosure: ArrayElementDisclosure = { salt: salt, value: arrayElement }
  return encodeDisclosure(disclosure)
}

function encodeDisclosure(disclosure: Disclosure) {
  const stringifiedElements = stringifyWorkaround(disclosure)
  const asBytes = stringToBytes(stringifiedElements)
  return bytesToBase64url(asBytes)
}

/**
 * JSON.stringify workaround for arrays, in order to match SD-JWT spec.
 *
 * Stringify element-wise and join with commas, space-separated.
 *
 * @param {Disclosure} disclosure
 * @return {*}  {string}
 */
function stringifyWorkaround(disclosure: Disclosure): string {
  const elements = [JSON.stringify(disclosure.salt)]

  if (Object.prototype.hasOwnProperty.call(disclosure, 'key')) {
    const objectPropertyDisclosure = disclosure as ObjectPropertyDisclosure
    elements.push(JSON.stringify(objectPropertyDisclosure.key))
  }

  elements.push(JSON.stringify(disclosure.value))

  return `[${elements.join(', ')}]`
}

/**
 *
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
  console.log('sd_alg', sd_alg)
  throw new Error(`Unsupported sd_alg: ${sd_alg}`)
}
/**
 *
 *
 * @export
 * @param {Partial<JWTPayload>} payload
 * @param {Partial<JWTPayload>} redactedPayload
 * @param {JWTOptions} { issuer, signer, alg, expiresIn, canonicalize }
 * @param {Partial<JWTHeader>} [header={}]
 * @return {*}  {Promise<string>}
 */
export async function createSdJWT(
  payload: Partial<JWTPayload>,
  redactedPayload: Partial<JWTPayload>,
  { issuer, signer, alg, expiresIn, canonicalize }: JWTOptions,
  header: Partial<JWTHeader> = {}
): Promise<string> {
  const { sdJwtPart, disclosures } = makeSelectivelyDisclosable(redactedPayload)
  const mergedJwt = { ...payload, ...sdJwtPart }
  const jwt = await createJWT(mergedJwt, { issuer, signer, alg, expiresIn, canonicalize }, header)

  return formSdJwt(jwt, disclosures)
}

interface SdJwtData {
  sdJwtPart: Partial<SdJWTPayload>
  disclosures: string[]
}

export function makeSelectivelyDisclosable(sdParts: Partial<JWTPayload>, sd_alg: string = DEFAULT_SD_ALG): SdJwtData {
  const sdJwtPart: Partial<SdJWTPayload> = {
    _sd_alg: sd_alg,
  }

  const sdArray: string[] = []
  const disclosures: string[] = []
  Object.entries(sdParts).forEach(([key, value]) => {
    const disclosure = createObjectPropertyDisclosure(key, value)
    const hash = hashDisclosure(disclosure, sd_alg)
    disclosures
    sdArray.push(hash)
  })
  if (sdArray.length > 0) {
    sdJwtPart._sd = sdArray
  }

  return {
    sdJwtPart,
    disclosures,
  }
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
  return `${jwt}~${encodedDisclosures.join('~')}~${kbJwt ? kbJwt : ''}}`
  //
}

// verify methods

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
 *  Decodes an SD-JWT and returns an object representing the payload
 *
 *  @example
 *  decodeSdJWT('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE1...~<Disclosure 1>~...<optional KB-JWT>')
 *
 * @export
 * @param {string} sdJwt                an SD-JWT to verify
 * @param {boolean} [recurse=true]      whether to recurse into the payload to decode any nested SD-JWTs
 * @return {*}  {JWTDecoded}            the decoded JWT
 */
export function decodeSdJWT(sdJwt: string, recurse: boolean = true): JWTDecoded {
  const parts = sdJwt.split(DISCLOSURE_SEPARATOR)

  // Last element is either empty or a KB-JWT
  const kbJwt = parts.pop() || ''
  console.log('kbJwt', kbJwt) // TODO: handle

  const [jwt, ...disclosures] = parts

  const decodedJwt = decodeJWT(jwt, recurse)
  const sdAlg = decodedJwt.payload._sd_alg || DEFAULT_SD_ALG
  const jwtPayload = decodedJwt.payload

  const disclosureMap = buildDigestDisclosureMap(disclosures, sdAlg)

  const converted = expandDisclosures(jwtPayload, disclosureMap, recurse) as JWTPayload
  decodedJwt.payload = converted // TODO
  return decodedJwt
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
