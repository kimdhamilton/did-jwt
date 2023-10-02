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
  EXAMPLE_1_DECODED,
  EXAMPLE_1_JWT,
  EXAMPLE_1_KB_DECODED,
  EXAMPLE_1_KB_JWT,
  HASH_DISCLOSURE_TEST_CASES,
  OBJECT_PROPERTY_DISCLOSURE_TEST_CASES,
} from './sd-jwt-vectors.js'

describe('SD-JWT()', () => {
  const BASE64_REGEX = new RegExp(/^[-A-Za-z0-9_/]*={0,3}$/)

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

  describe('createSalt', () => {
    it('createSalt() returns a string that is base64url encoded', () => {
      const salt = createSalt()
      expect(BASE64_REGEX.test(salt)).toBeTruthy()
    })

    it('createSalt(number) returns a string that is base64url encoded', () => {
      const salt = createSalt(32)
      expect(BASE64_REGEX.test(salt)).toBeTruthy()
    })
  })
  describe('createObjectPropertyDisclosure', () => {
    it('createObjectPropertyDisclosure returns a string that is base64url encoded', () => {
      const key = 'key'
      const value = 'value'
      const disclosure = createObjectPropertyDisclosure(key, value)

      expect(BASE64_REGEX.test(disclosure)).toBeTruthy()
    })

    it('createObjectPropertyDisclosure (with salt) returns a string that is base64url encoded', () => {
      const salt = createSalt()
      const key = 'key'
      const value = 'value'
      const disclosure = createObjectPropertyDisclosure(key, value, {
        salt,
      })

      expect(BASE64_REGEX.test(disclosure)).toBeTruthy()
    })

    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'createObjectPropertyDisclosure matches SD-JWT spec output with stringify override (key: $key, value: $value, salt: $salt)',
      ({ key, value, salt, disclosure }) => {
        const actual = createObjectPropertyDisclosure(key, value, {
          salt,
          ...SPEC_COMPAT_OPTIONS,
        })
        expect(actual).toEqual(disclosure)
      }
    )

    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'createObjectPropertyDisclosure matches expected output with default stringify (key: $key, value: $value, salt: $salt)',
      ({ key, value, salt, defaultDisclosure }) => {
        const actual = createObjectPropertyDisclosure(key, value, {
          salt,
        })
        expect(actual).toEqual(defaultDisclosure)
      }
    )
  })

  describe('createArrayElementDisclosure', () => {
    it.each([
      ['FR', 'lklxF5jMYlGTPUovMNIvCA', 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0'],
      ['US', 'lklxF5jMYlGTPUovMNIvCA', 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0'],
      ['DE', 'nPuoQnkRFq3BIeAm7AnXFA', 'WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0'],
    ])(
      'createArrayElementDisclosure matches SD-JWT spec output (arrayElement: %s, salt: %s)',
      (arrayElement, salt, expected) => {
        const disclosure = createArrayElementDisclosure(arrayElement, {
          salt,
          ...SPEC_COMPAT_OPTIONS,
        })
        expect(disclosure).toEqual(expected)
      }
    )
  })

  describe('hashDisclosure', () => {
    it.each(HASH_DISCLOSURE_TEST_CASES)(
      'hashDisclosure matches SD-JWT spec output (%s, %s)',
      (disclosure, expectedHash) => {
        const hash = hashDisclosure(disclosure)
        expect(hash).toEqual(expectedHash)
      }
    )
  })

  describe('makeSelectivelyDisclosable', () => {
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

  describe('parseObjectPropertyDisclosure ', () => {
    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'parseObjectPropertyDisclosure roundtrips (with disclosure created by spec stringify override) (key: $key, value: $value, salt: $salt)',
      ({ disclosure, key, value, salt }) => {
        const decoded = parseObjectPropertyDisclosure(disclosure)
        expect(decoded).toMatchObject({ key, value, salt })
      }
    )

    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'parseObjectPropertyDisclosure roundtrips (key: $key, value: $value, salt: $salt)',
      ({ defaultDisclosure, key, value, salt }) => {
        const decoded = parseObjectPropertyDisclosure(defaultDisclosure)
        expect(decoded).toMatchObject({ key, value, salt })
      }
    )
  })

  describe('createSdJWT', () => {
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

      console.log(JSON.stringify(decoded, null, 2))

      expect(decoded).toMatchObject(expected)
    })
  })

  describe('decodeSdJWT', () => {
    it('decodes an SD-JWT without key binding', () => {
      const decoded = decodeSdJWT(EXAMPLE_1_JWT, true)
      expect(decoded).toMatchObject(EXAMPLE_1_DECODED)
    })

    it('decodes an SD-JWT with key binding', () => {
      const decoded = decodeSdJWT(EXAMPLE_1_KB_JWT, true)
      expect(decoded).toMatchObject(EXAMPLE_1_KB_DECODED)
    })
  })

  describe('verifySdJWT', () => {})
})
