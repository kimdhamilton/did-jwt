import {
  createArrayElementDisclosure,
  createObjectPropertyDisclosure,
  createSalt,
  makeSelectivelyDisclosable,
  decodeSdJWT,
  hashDisclosure,
  parseObjectPropertyDisclosure,
  createSdJWT,
} from '../SD-JWT.js'
import { ES256KSigner } from '../signers/ES256KSigner.js'
import { hexToBytes } from '../util.js'
import {
  ARRAY_ELEMENT_DISCLOSURE_TEST_CASES,
  EXAMPLE_1_DECODED,
  EXAMPLE_1_JWT,
  EXAMPLE_1_KB_DECODED,
  EXAMPLE_1_KB_JWT,
  HASH_DISCLOSURE_TEST_CASES,
  OBJECT_PROPERTY_DISCLOSURE_TEST_CASES,
} from './sd-jwt-vectors.js'

describe('SD-JWT()', () => {
  const BASE64_URL_REGEX = new RegExp(/^[-A-Za-z0-9_/]*={0,3}$/)

  /**
   * If set to true, this uses a special stringify function that allows an
   * exact match for the SD-JWT spec examples.
   *
   * Matching the spec outputs also requires the use of a pre-defined salt,
   * which is provided in the test cases. (@link sd-jwt-vectors.js)
   *
   * Because the exact stringify formatting is not specified by the spec,
   * this is not the default behavior. If not enabled, the default
   * JSON.stringify() function, with no args, will be used.
   */
  const SPEC_COMPAT_OPTIONS = {
    specCompatStringify: true,
  }

  const audAddress = '0x20c769ec9c0996ba7737a4826c2aaff00b1b2040'
  const aud = `did:ethr:${audAddress}`
  const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  const did = `did:ethr:${address}`
  const alg = 'ES256K'

  const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
  const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
  const signer = ES256KSigner(hexToBytes(privateKey))

  describe('createSalt()', () => {
    it('returns a string that is base64url encoded', () => {
      const salt = createSalt()
      expect(BASE64_URL_REGEX.test(salt)).toBeTruthy()
    })

    it('returns a string that is base64url encoded (with pre-defined salt) ', () => {
      const salt = createSalt(32)
      expect(BASE64_URL_REGEX.test(salt)).toBeTruthy()
    })
  })

  /* SD-JWT spec (5.2.1) tests  */
  describe('createObjectPropertyDisclosure()', () => {
    it('returns a string that is base64url encoded', () => {
      const key = 'someKey'
      const value = 'someValue'
      const disclosure = createObjectPropertyDisclosure(key, value)

      expect(BASE64_URL_REGEX.test(disclosure)).toBeTruthy()
    })

    it('returns a string that is base64url encoded (given a pre-defined salt)', () => {
      const salt = createSalt()
      const key = 'someKey'
      const value = 'someValue'
      const disclosure = createObjectPropertyDisclosure(key, value, {
        salt,
      })

      expect(BASE64_URL_REGEX.test(disclosure)).toBeTruthy()
    })

    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'matches SD-JWT spec output with specCompatStringify (key: $key, value: $value, salt: $salt)',
      ({ key, value, salt, specDisclosure }) => {
        const actual = createObjectPropertyDisclosure(key, value, {
          salt,
          ...SPEC_COMPAT_OPTIONS,
        })
        expect(actual).toEqual(specDisclosure)
      }
    )

    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'matches expected output with default JSON.stringify() (key: $key, value: $value, salt: $salt)',
      ({ key, value, salt, defaultDisclosure }) => {
        const actual = createObjectPropertyDisclosure(key, value, {
          salt,
        })
        expect(actual).toEqual(defaultDisclosure)
      }
    )
  })

  /* SD-JWT spec (5.2.2) tests */
  describe('createArrayElementDisclosure()', () => {
    it('returns a string that is base64url encoded', () => {
      const arrayElement = 'someValue'
      const disclosure = createArrayElementDisclosure(arrayElement)

      expect(BASE64_URL_REGEX.test(disclosure)).toBeTruthy()
    })

    it('returns a string that is base64url encoded (given a pre-defined salt) ', () => {
      const salt = createSalt()
      const arrayElement = 'someValue'
      const disclosure = createArrayElementDisclosure(arrayElement)

      expect(BASE64_URL_REGEX.test(disclosure)).toBeTruthy()
    })

    it.each(ARRAY_ELEMENT_DISCLOSURE_TEST_CASES)(
      'matches SD-JWT spec output with specCompatStringify (arrayElement: $arrayElement, salt: $salt)',
      ({ arrayElement, salt, specDisclosure }) => {
        const actual = createArrayElementDisclosure(arrayElement, {
          salt,
          ...SPEC_COMPAT_OPTIONS,
        })
        expect(actual).toEqual(specDisclosure)
      }
    )

    it.each(ARRAY_ELEMENT_DISCLOSURE_TEST_CASES)(
      'matches expected output with default JSON.stringify() (arrayElement: $arrayElement, salt: $salt)',
      ({ arrayElement, salt, defaultDisclosure }) => {
        const actual = createArrayElementDisclosure(arrayElement, {
          salt,
        })
        expect(actual).toEqual(defaultDisclosure)
      }
    )
  })

  /* SD-JWT spec (5.3) tests */
  describe('hashDisclosure()', () => {
    it.each(HASH_DISCLOSURE_TEST_CASES)(
      'matches SD-JWT spec output (disclosure: %s, expectedHash: %s)',
      (disclosure, expectedHash) => {
        const hash = hashDisclosure(disclosure)
        expect(hash).toEqual(expectedHash)
      }
    )
  })

  describe('makeSelectivelyDisclosable()', () => {
    it('passes basic test', () => {
      // TODO: ensure this is right
      const expected = {
        _sd: ['1d8R5b38fnDx0YuWnSNtr0mbNrnh5cjwsDm0OfCMqRc', 'nSu9QF-F0nagTViHF1_ifEivC1v-eDn4wRXOtzrj-hE'],
        _sd_alg: 'sha-256',
      }
      const disclosureMap = makeSelectivelyDisclosable({ key1: 'value1', key2: 'value2' })

      expect(disclosureMap).toBeDefined()
      // TODO
    })

    // TODO: this won't match because salts are different
    it('matches SD-JWT', () => {
      const input = {
        given_name: 'John',
        family_name: 'Doe',
        email: 'johndoe@example.com',
        phone_number: '+1-202-555-0101',
        phone_number_verified: true,
        birthdate: '1940-01-01',
        updated_at: 1570000000,
        /*             address: {
                          "street_address": "123 Main St",
                          "locality": "Anytown",
                          "region": "Anystate",
                          "country": "US"
                      },*/
      }

      const sds = makeSelectivelyDisclosable(input)
      //  console.log(JSON.stringify(sds, null, 2))
    })
  })

  /* Ensures disclosures roundtrip */
  describe('parseObjectPropertyDisclosure() ', () => {
    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'parses disclosures stringified with specCompatStringify (specDisclosure: $specDisclosure)',
      ({ specDisclosure, key, value, salt }) => {
        const decoded = parseObjectPropertyDisclosure(specDisclosure)
        expect(decoded).toMatchObject({ key, value, salt })
      }
    )

    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'parses disclosures stringified with default JSON.stringify() (defaultDisclosure: $defaultDisclosure)',
      ({ defaultDisclosure, key, value, salt }) => {
        const decoded = parseObjectPropertyDisclosure(defaultDisclosure)
        expect(decoded).toMatchObject({ key, value, salt })
      }
    )
  })

  describe('createSdJWT()', () => {
    it('creates an SD-JWT without key binding', async () => {
      const expected = {
        header: {
          alg: 'ES256',
          typ: 'JWT',
        },
        payload: {
          _sd_alg: 'sha-256',
          given_name: 'John',
          family_name: 'Doe',
          email: 'johndoe@example.com',
          phone_number: '+1-202-555-0101',
          phone_number_verified: true,
          birthdate: '1940-01-01',
        },
      }

      const clearClaims = {
        given_name: 'John',
        family_name: 'Doe',
        updated_at: 1570000000,
      }

      const sdClaims = {
        email: 'johndoe@example.com',
        phone_number: '+1-202-555-0101',
        phone_number_verified: true,
        birthdate: '1940-01-01',
      }

      const disclosureMap = makeSelectivelyDisclosable(sdClaims)

      const sdJwtInput = {
        _sd_alg: 'sha-256',
        _sd: [...disclosureMap.keys()],
        ...clearClaims,
      }

      const sdJwt = await createSdJWT(
        sdJwtInput,
        {
          issuer: did,
          signer,
          disclosures: [...disclosureMap.values()],
        },
        { alg: 'ES256' }
      )

      // verify result by decoding
      const decoded = decodeSdJWT(sdJwt, true)
      expect(decoded).toMatchObject(expected)
    })
  })

  describe('decodeSdJWT()', () => {
    it('decodes SD-JWT spec example (without key binding)', () => {
      const decoded = decodeSdJWT(EXAMPLE_1_JWT, true)
      expect(decoded).toMatchObject(EXAMPLE_1_DECODED)
    })

    it('decodes SD-JWT spec example (with key binding)', () => {
      const decoded = decodeSdJWT(EXAMPLE_1_KB_JWT, true)
      expect(decoded).toMatchObject(EXAMPLE_1_KB_DECODED)
    })
  })

  describe('verifySdJWT()', () => {
    it('ignores undisclosed digests', () => {})

    it('rejects an ill-formed SD-JWT', () => {})

    it('rejects an SD-JWT with an invalid signature', () => {})

    it('rejects an SD-JWT with unsupported sd_alg', () => {})

    it('rejects an SD-JWT with an ill-formed array disclosure', () => {})
    it('rejects an SD-JWT with an ill-formed object disclosure', () => {})

    it('rejects an SD-JWT with a repeated claim', () => {})

    it('rejects an SD-JWT with digests found more than once', () => {})
  })

  describe('E2E - Holder', () => {
    it('reveals a subset of disclosures', () => {
      // Step 0: holder receives EXAMPLE_1_JWT from issuer

      const decoded = decodeSdJWT(EXAMPLE_1_JWT, true)
      expect(decoded).toMatchObject(EXAMPLE_1_DECODED)
    })
  })

  describe('E2E - Verifier', () => {})

  describe('E2E - Decoy', () => {})
})
