import {
  createArrayElementDisclosure,
  createObjectPropertyDisclosure,
  createSalt,
  makeSelectivelyDisclosable,
  decodeSdJWT,
  hashDisclosure,
  parseObjectPropertyDisclosure,
} from '../SD-JWT.js'
import { HASH_DISCLOSURE_TEST_CASES, OBJECT_PROPERTY_DISCLOSURE_TEST_CASES } from './sd-jwt-vectors.js'

describe('SD-JWT()', () => {
  const BASE64_REGEX = new RegExp(/^[-A-Za-z0-9_/]*={0,3}$/)

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
      const disclosure = createObjectPropertyDisclosure(key, value, salt)

      expect(BASE64_REGEX.test(disclosure)).toBeTruthy()
    })

    // TODO: fix and enable failing tests
    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'createObjectPropertyDisclosure matches SD-JWT spec output (%s)',
      ({ key, value, salt, disclosure }) => {
        const actual = createObjectPropertyDisclosure(key, value, salt)
        expect(actual).toEqual(disclosure)
      }
    )
  })

  describe('createArrayElementDisclosure', () => {
    it.each([
      ['FR', 'lklxF5jMYlGTPUovMNIvCA', 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0'],
      ['US', 'lklxF5jMYlGTPUovMNIvCA', 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0'],
      ['DE', 'nPuoQnkRFq3BIeAm7AnXFA', 'WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0'],
    ])('createArrayElementDisclosure matches SD-JWT spec output (%s, %s)', (arrayElement, salt, expected) => {
      const disclosure = createArrayElementDisclosure(arrayElement, salt)
      expect(disclosure).toEqual(expected)
    })
  })

  it.each(HASH_DISCLOSURE_TEST_CASES)('hashDisclosure matches SD-JWT spec output (%s)', (disclosure, expectedHash) => {
    const hash = hashDisclosure(disclosure)
    expect(hash).toEqual(expectedHash)
  })

  it('createSelectiveDisclosures basic test', () => {
    // TODO: ensure this is right
    const expected = {
      _sd: ['1d8R5b38fnDx0YuWnSNtr0mbNrnh5cjwsDm0OfCMqRc', 'nSu9QF-F0nagTViHF1_ifEivC1v-eDn4wRXOtzrj-hE'],
      _sd_alg: 'sha-256',
    }
    const sds = makeSelectivelyDisclosable({ key1: 'value1', key2: 'value2' })
    expect(sds).toBeDefined()
  })

  // TODO: this won't match because salts are different
  it('createSelectiveDisclosures matches SD-JWT', () => {
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
    console.log(JSON.stringify(sds, null, 2))
  })

  describe('parseObjectPropertyDisclosure', () => {
    it.each(OBJECT_PROPERTY_DISCLOSURE_TEST_CASES)(
      'parseObjectPropertyDisclosure roundtrips (%s)',
      ({ disclosure, key, value, salt }) => {
        const decoded = parseObjectPropertyDisclosure(disclosure)
        expect(decoded).toMatchObject({ key, value, salt })
      }
    )
  })

  /*
  describe('validateSdJwt', () => {
    it('validateSdJwt returns a decoded JWT', () => {
      const example =
        'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~'
      const decoded = decodeSdJWT(example, true)
      console.log(JSON.stringify(decoded, null, 2))
    })



  /*
      it('extractSdDigests', () => {
          const jwtPayload = {
              "_sd": [
                "-aSznId9mWM8ocuQolCllsxVggq1-vHW4OtnhUtVmWw",
                "IKbrYNn3vA7WEFrysvbdBJjDDU_EvQIr0W18vTRpUSg",
                "otkxuT14nBiwzNJ3MPaOitOl9pVnXOaEHal_xkyNfKI"
              ],
              iss: "https://example.com/issuer",
              iat: 1683000000,
              exp: 1883000000,
              verified_claims: {
                verification: {
                  "_sd": [
                    "7h4UE9qScvDKodXVCuoKfKBJpVBfXMF_TmAGVaZe3Sc",
                    "vTwe3raHIFYgFA3xaUD2aMxFz5oDo8iBu05qKlOg9Lw"
                  ],
                  trust_framework: "de_aml",
                  evidence: [
                    {
                      "...": "tYJ0TDucyZZCRMbROG4qRO5vkPSFRxFhUELc18CSl3k"
                    }
                  ]
                },
                claims: {
                  "_sd": [
                    "RiOiCn6_w5ZHaadkQMrcQJf0Jte5RwurRs54231DTlo",
                    "S_498bbpKzB6Eanftss0xc7cOaoneRr3pKr7NdRmsMo",
                    "WNA-UNK7F_zhsAb9syWO6IIQ1uHlTmOU8r8CvJ0cIMk",
                    "Wxh_sV3iRH9bgrTBJi-aYHNCLt-vjhX1sd-igOf_9lk",
                    "_O-wJiH3enSB4ROHntToQT8JmLtz-mhO2f1c89XoerQ",
                    "hvDXhwmGcJQsBCA2OtjuLAcwAMpDsaU0nkovcKOqWNE"
                  ]
                }
              },
              "_sd_alg": "sha-256"
            }
  
            const expectedDigests = [
            "-aSznId9mWM8ocuQolCllsxVggq1-vHW4OtnhUtVmWw",
            "IKbrYNn3vA7WEFrysvbdBJjDDU_EvQIr0W18vTRpUSg",
            "otkxuT14nBiwzNJ3MPaOitOl9pVnXOaEHal_xkyNfKI",
            "7h4UE9qScvDKodXVCuoKfKBJpVBfXMF_TmAGVaZe3Sc",
            "vTwe3raHIFYgFA3xaUD2aMxFz5oDo8iBu05qKlOg9Lw",
            "tYJ0TDucyZZCRMbROG4qRO5vkPSFRxFhUELc18CSl3k",
            "RiOiCn6_w5ZHaadkQMrcQJf0Jte5RwurRs54231DTlo",
            "S_498bbpKzB6Eanftss0xc7cOaoneRr3pKr7NdRmsMo",
            "WNA-UNK7F_zhsAb9syWO6IIQ1uHlTmOU8r8CvJ0cIMk",
            "Wxh_sV3iRH9bgrTBJi-aYHNCLt-vjhX1sd-igOf_9lk",
            "_O-wJiH3enSB4ROHntToQT8JmLtz-mhO2f1c89XoerQ",
            "hvDXhwmGcJQsBCA2OtjuLAcwAMpDsaU0nkovcKOqWNE"]
  
            const result = extractSdDigests(jwtPayload)
            expect (result).toMatchObject(expectedDigests)
                    })*/
})
