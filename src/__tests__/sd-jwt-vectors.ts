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

export const OBJECT_PROPERTY_DISCLOSURE_TEST_CASES = [
  {
    disclosure: 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0',
    key: 'family_name',
    value: 'Möbius',
    salt: '_26bc4LT-ac6q2KI6cBW5es',
  },
  {
    disclosure: 'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd',
    key: 'given_name',
    value: 'John',
    salt: '2GLC42sKQveCfGfryNRN9w',
  },
  {
    disclosure: 'WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd',
    key: 'family_name',
    value: 'Doe',
    salt: 'eluV5Og3gSNII8EYnsxA_A',
  },
  {
    disclosure: 'WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ',
    key: 'email',
    value: 'johndoe@example.com',
    salt: '6Ij7tM-a5iVPGboS5tmvVA',
  },
  {
    disclosure: 'WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ',
    key: 'phone_number',
    value: '+1-202-555-0101',
    salt: 'eI8ZWm9QnKPpNPeNenHdhQ',
  },
  {
    disclosure: 'WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd',
    key: 'phone_number_verified',
    value: true,
    salt: 'Qg_O64zqAxe412a108iroA',
  },
  {
    disclosure: 'WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0',
    key: 'birthdate',
    value: '1940-01-01',
    salt: 'Pc33JM2LchcU_lHggv_ufQ',
  },
  {
    disclosure: 'WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ',
    key: 'updated_at',
    value: 1570000000,
    salt: 'G02NSrQfjFXQ7Io09syajA',
  },
  {
    disclosure:
      'WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0',
    key: 'address',
    value: { street_address: '123 Main St', locality: 'Anytown', region: 'Anystate', country: 'US' },
    salt: 'AJx-095VPrpTtN4QMOqROA',
  },
]
