/**
 * Test vectors come primarily from section 5.5 of the SD-JWT spec.
 */
export const EXAMPLE_1_JWT =
  'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~'

export const EXAMPLE_1_KB_JWT =
  'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE2ODgxNjA0ODN9.tKnLymr8fQfupOgvMgBK3GCEIDEzhgta4MgnxYm9fWGMkqrz2R5PSkv0I-AXKXtIF6bdZRbjL-t43vC87jVoZQ'

// TODO: check against spec
export const EXAMPLE_1_DECODED = {
  header: {
    alg: 'ES256',
  },
  payload: {
    iss: 'https://example.com/issuer',
    iat: 1683000000,
    exp: 1883000000,
    sub: 'user_42',
    nationalities: ['US', 'DE'],
    cnf: {
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
        y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
      },
    },
    updated_at: 1570000000,
    email: 'johndoe@example.com',
    phone_number: '+1-202-555-0101',
    family_name: 'Doe',
    phone_number_verified: true,
    address: {
      street_address: '123 Main St',
      locality: 'Anytown',
      region: 'Anystate',
      country: 'US',
    },
    birthdate: '1940-01-01',
    given_name: 'John',
  },
  signature: 'kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg',
  data: 'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0',
}

export const EXAMPLE_1_KB_DECODED = {
  header: {
    alg: 'ES256',
  },
  payload: {
    iss: 'https://example.com/issuer',
    iat: 1683000000,
    exp: 1883000000,
    sub: 'user_42',
    nationalities: ['US'],
    cnf: {
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
        y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
      },
    },
    family_name: 'Doe',
    address: {
      street_address: '123 Main St',
      locality: 'Anytown',
      region: 'Anystate',
      country: 'US',
    },
    given_name: 'John',
  },
  data: 'eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0',
  kb_jwt:
    'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE2ODgxNjA0ODN9.tKnLymr8fQfupOgvMgBK3GCEIDEzhgta4MgnxYm9fWGMkqrz2R5PSkv0I-AXKXtIF6bdZRbjL-t43vC87jVoZQ',
}

/* Following test cases demonstrate 5.7. Nested Data in SD-JWTs. Decooded versions of all options should match ADDRESS_DECODED */
export const ADDRESS_DECODED = {
  header: {
    alg: 'ES256K',
    typ: 'JWT',
  },
  payload: {
    iat: 1683000000,
    exp: 1883000000,
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    sub: '6c5c0a49-b589-431d-bae7-219122a9ec2c',
    address: {
      street_address: 'Schulstr. 12',
      locality: 'Schulpforta',
      region: 'Sachsen-Anhalt',
      country: 'DE',
    },
  },
}

export const ADDRESS_OPTION_1 = {
  _sd: ['fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do'],
  iat: 1683000000,
  exp: 1883000000,
  sub: '6c5c0a49-b589-431d-bae7-219122a9ec2c',
  _sd_alg: 'sha-256',
}

export const ADDRESS_OPTION_1_DISCLOSURE =
  'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ'

export const ADDRESS_OPTION_1_SD_JWT =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2ODMwMDAwMDAsImV4cCI6MTg4MzAwMDAwMCwiX3NkIjpbImZPQlVTUXZvNDZ5UU8td1J3WEJjR3F2bmJLSXVlSVNFTDk2MV9TamQ0ZG8iXSwic3ViIjoiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ.97TwTiyX-LBNR-kYid6KNmzSlzkquhnpo2oT-xN6ls1cZDLPhFIeHYYlO50bznIG5krxT3qo1ohjMp_iDB4E9g~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~'
export const ADDRESS_OPTION_2 = {
  iat: 1683000000,
  exp: 1883000000,
  sub: '6c5c0a49-b589-431d-bae7-219122a9ec2c',
  address: {
    _sd: [
      '6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0',
      '9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM',
      'KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88',
      'WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM',
    ],
  },
  _sd_alg: 'sha-256',
}

export const ADDRESS_OPTION_2_DISCLOSURES = [
  'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd',
  'WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0',
  'WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd',
  'WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ',
]

export const ADDRESS_OPTION_2_SD_JWT =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2ODMwMDAwMDAsImV4cCI6MTg4MzAwMDAwMCwic3ViIjoiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwiYWRkcmVzcyI6eyJfc2QiOlsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsIjlnalZ1WHRkRlJPQ2dScnROY0dVWG1GNjVyZGV6aV82RXJfajc2a21ZeU0iLCJLVVJEUGg0WkMxOS0zdGl6LURmMzlWOGVpZHkxb1YzYTNIMURhMk4wZzg4IiwiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfSwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ._R4o6I02mGhwMoZbwSxxp9g605pLFVnjw6zCUsu_px5QBEkIflI1_J7os2hjLxfCtY_hZmgKNGRiYDhnb4DluA~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ~'

export const ADDRESS_OPTION_3 = {
  _sd: ['HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg'],
  iat: 1683000000,
  exp: 1883000000,
  sub: '6c5c0a49-b589-431d-bae7-219122a9ec2c',
  _sd_alg: 'sha-256',
}

export const ADDRESS_OPTION_3_DISCLOSURES = [
  'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd',
  'WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0',
  'WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd',
  'WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ',
  'WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsICI5Z2pWdVh0ZEZST0NnUnJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwgIktVUkRQaDRaQzE5LTN0aXotRGYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfV0',
]

export const ADDRESS_OPTION_3_SD_JWT =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2ODMwMDAwMDAsImV4cCI6MTg4MzAwMDAwMCwiX3NkIjpbIkh2cktYNmZQVjB2OUtfeUNWRkJpTEZIc01heGNEXzExNEVtNlZUOHgxbGciXSwic3ViIjoiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ.fwmhEaJJ7FcmY6NPknEq6OhRD3fMMUXppXmHkEsuanY-ntJHLfHOZxNfINx3f3X8K7fMYwhSSbmu3zG9l_aPfA~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsICI5Z2pWdVh0ZEZST0NnUnJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwgIktVUkRQaDRaQzE5LTN0aXotRGYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfV0~'

export const ADDRESS_OPTION_2_JWT_ONLY =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2ODMwMDAwMDAsImV4cCI6MTg4MzAwMDAwMCwic3ViIjoiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwiYWRkcmVzcyI6eyJfc2QiOlsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsIjlnalZ1WHRkRlJPQ2dScnROY0dVWG1GNjVyZGV6aV82RXJfajc2a21ZeU0iLCJLVVJEUGg0WkMxOS0zdGl6LURmMzlWOGVpZHkxb1YzYTNIMURhMk4wZzg4IiwiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfSwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQifQ._R4o6I02mGhwMoZbwSxxp9g605pLFVnjw6zCUsu_px5QBEkIflI1_J7os2hjLxfCtY_hZmgKNGRiYDhnb4DluA'

export const ADDRESS_SUBSET_DECODED = {
  header: {
    alg: 'ES256K',
    typ: 'JWT',
  },
  payload: {
    iat: 1683000000,
    exp: 1883000000,
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    sub: '6c5c0a49-b589-431d-bae7-219122a9ec2c',
    address: {
      street_address: 'Schulstr. 12',
    },
  },
}

export const HASH_DISCLOSURE_TEST_CASES = [
  ['WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0', 'uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY'],
  ['WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0', 'w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs'],
  ['WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd', 'jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4'],
  ['WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd', 'TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo'],
  [
    'WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ',
    'JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE',
  ],
  [
    'WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ',
    'PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI',
  ],
  [
    'WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd',
    'XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM',
  ],
  [
    'WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0',
    'XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE',
  ],
  [
    'WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0',
    'gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM',
  ],
  [
    'WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ',
    'CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI',
  ],
  ['WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0', 'pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo'],
  ['WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0', '7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0'],
]

/**
 * Test cases for object property disclosure. When creating a disclosure, 2 things are required
 * to match the SD-JWT spec output: 1) must use the same salt 2) must stringify in the same way.
 *
 * This tests all disclosures in the spec except for the object value, where the stringify
 * method is even more complicated. That is tested separately.
 *
 * { street_address: '123 Main St', locality: 'Anytown', region: 'Anystate', country: 'US' },
 */
export const OBJECT_PROPERTY_DISCLOSURE_TEST_CASES = [
  {
    specDisclosure: 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0',
    defaultDisclosure: 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd',
    key: 'family_name',
    value: 'Möbius',
    salt: '_26bc4LT-ac6q2KI6cBW5es',
  },
  {
    specDisclosure: 'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd',
    defaultDisclosure: 'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ',
    key: 'given_name',
    value: 'John',
    salt: '2GLC42sKQveCfGfryNRN9w',
  },
  {
    specDisclosure: 'WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd',
    defaultDisclosure: 'WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ',
    key: 'family_name',
    value: 'Doe',
    salt: 'eluV5Og3gSNII8EYnsxA_A',
  },
  {
    specDisclosure: 'WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ',
    defaultDisclosure: 'WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0',
    key: 'email',
    value: 'johndoe@example.com',
    salt: '6Ij7tM-a5iVPGboS5tmvVA',
  },
  {
    specDisclosure: 'WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ',
    defaultDisclosure: 'WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0',
    key: 'phone_number',
    value: '+1-202-555-0101',
    salt: 'eI8ZWm9QnKPpNPeNenHdhQ',
  },
  {
    specDisclosure: 'WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd',
    defaultDisclosure: 'WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIix0cnVlXQ',
    key: 'phone_number_verified',
    value: true,
    salt: 'Qg_O64zqAxe412a108iroA',
  },
  {
    specDisclosure: 'WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0',
    defaultDisclosure: 'WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd',
    key: 'birthdate',
    value: '1940-01-01',
    salt: 'Pc33JM2LchcU_lHggv_ufQ',
  },
  {
    specDisclosure: 'WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ',
    defaultDisclosure: 'WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwidXBkYXRlZF9hdCIsMTU3MDAwMDAwMF0',
    key: 'updated_at',
    value: 1570000000,
    salt: 'G02NSrQfjFXQ7Io09syajA',
  },
]

export const ARRAY_ELEMENT_DISCLOSURE_TEST_CASES = [
  {
    arrayElement: 'FR',
    salt: 'lklxF5jMYlGTPUovMNIvCA',
    specDisclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0',
    defaultDisclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwiRlIiXQ',
  },
  {
    arrayElement: 'US',
    salt: 'lklxF5jMYlGTPUovMNIvCA',
    specDisclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0',
    defaultDisclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwiVVMiXQ',
  },
  {
    arrayElement: 'DE',
    salt: 'nPuoQnkRFq3BIeAm7AnXFA',
    specDisclosure: 'WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0',
    defaultDisclosure: 'WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwiREUiXQ',
  },
]

/*
    This is an unsupported SD-JWT. It has a repeated claim, hiddenValue1: "value1",
    in the clear and _sd claims / disclosures.

    {
        "_sd_alg": "sha-256",
        "_sd": [
            "ZALDwLOxAxL4V0GwtlpfYwUh--w-XfAQQ3WyYBnDak0",
            "Pq7Mj2hPb-DjVuEH54D3HPTMfahASjmj2V9qOdRws2A"
        ],
        "clearValue1": "value3",
        "hiddenValue1": "value1",
        "iss": "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74"
    } 
*/
export const SD_JWT_REPEATED_CLAIM =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2OTY1MzEzMTcsImhpZGRlblZhbHVlMSI6InZhbHVlMSIsIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIlpBTER3TE94QXhMNFYwR3d0bHBmWXdVaC0tdy1YZkFRUTNXeVlCbkRhazAiLCJQcTdNajJoUGItRGpWdUVINTREM0hQVE1mYWhBU2ptajJWOXFPZFJ3czJBIl0sImNsZWFyVmFsdWUxIjoidmFsdWUzIiwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0._yjhqC2nyg9cBg0Uq6SwMWHhfQ3MJKfa5eTFYNSwDE5CuXknuZ9VKlVVCA0eB9kSN3D8RTM_ILi3b1QfpNd_rw~WyJsNW1UMEp0b0pOVEc2SzJPLWM5Nmp3IiwiaGlkZGVuVmFsdWUxIiwidmFsdWUxIl0~WyJUN2VzRUJaOVdybmV1NXNraEMyRXN3IiwiaGlkZGVuVmFsdWUyIiwidmFsdWUyIl0~'
