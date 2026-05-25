const test = require('brittle')
const b4a = require('b4a')
const z32 = require('z32')
const { generate, parse } = require('./index.js')

const FIXED_SEED_HEX = '7260cb236be0ec6333225395c720180160501fdde442ed9400212bbe3e18e11b'

test('generate without seed produces a random invite', (t) => {
  const a = generate()
  const b = generate()

  t.is(typeof a.invite, 'string')
  t.ok(a.invite.startsWith('hs_'))
  t.is(a.seed.byteLength, 32)
  t.not(a.invite, b.invite, 'two random invites should differ')
})

test('generate returns the expected shape and sizes', (t) => {
  const out = generate(FIXED_SEED_HEX)

  t.is(out.seed.byteLength, 32)
  t.is(out.keyPair.publicKey.byteLength, 32)
  t.is(out.keyPair.secretKey.byteLength, 64)
  t.is(out.hmac.byteLength, 32)
  t.is(out.capability.byteLength, 32)
  t.is(typeof out.invite, 'string')
  t.ok(out.invite.startsWith('hs_'))
})

test('generate is deterministic for the same seed', (t) => {
  const a = generate(FIXED_SEED_HEX)
  const b = generate(FIXED_SEED_HEX)

  t.is(a.invite, b.invite)
  t.alike(a.keyPair.publicKey, b.keyPair.publicKey)
  t.alike(a.keyPair.secretKey, b.keyPair.secretKey)
  t.alike(a.capability, b.capability)
  t.alike(a.hmac, b.hmac)
})

test('generate accepts a hex string and an equivalent buffer interchangeably', (t) => {
  const fromHex = generate(FIXED_SEED_HEX)
  const fromBuf = generate(b4a.from(FIXED_SEED_HEX, 'hex'))

  t.is(fromHex.invite, fromBuf.invite)
  t.alike(fromHex.capability, fromBuf.capability)
})

test('generate rejects bad string seeds', (t) => {
  t.exception(() => generate('not-hex'), /64 hex chars/)
  t.exception(() => generate('abcd'), /64 hex chars/)
  t.exception(() => generate('z'.repeat(64)), /64 hex chars/)
  t.exception(() => generate(FIXED_SEED_HEX + '00'), /64 hex chars/)
})

test('generate rejects wrong-length buffer seeds', (t) => {
  t.exception(() => generate(b4a.alloc(0)), /32 bytes/)
  t.exception(() => generate(b4a.alloc(31)), /32 bytes/)
  t.exception(() => generate(b4a.alloc(33)), /32 bytes/)
  t.exception(() => generate(b4a.alloc(64)), /32 bytes/)
})

test('different seeds produce different keypairs, capabilities, and invites', (t) => {
  const a = generate(FIXED_SEED_HEX)
  const b = generate('a'.repeat(64))

  t.unlike(a.keyPair.publicKey, b.keyPair.publicKey)
  t.unlike(a.capability, b.capability)
  t.not(a.invite, b.invite)
})

test('parse roundtrips a freshly generated invite', (t) => {
  const out = generate(FIXED_SEED_HEX)
  const parsed = parse(out.invite)

  t.is(parsed.version, 1)
  t.alike(parsed.publicKey, out.keyPair.publicKey)
  t.alike(parsed.capability, out.capability)
})

test('parse rejects non-string input', (t) => {
  t.exception(() => parse(null), /Invalid invite format/)
  t.exception(() => parse(undefined), /Invalid invite format/)
  t.exception(() => parse(123), /Invalid invite format/)
  t.exception(() => parse({}), /Invalid invite format/)
  t.exception(() => parse(b4a.alloc(69)), /Invalid invite format/)
})

test('parse rejects strings missing the hs_ prefix', (t) => {
  const out = generate(FIXED_SEED_HEX)
  const body = out.invite.slice(3)

  t.exception(() => parse(body), /Invalid invite format/)
  t.exception(() => parse('xx_' + body), /Invalid invite format/)
  t.exception(() => parse('HS_' + body), /Invalid invite format/)
  t.exception(() => parse(''), /Invalid invite format/)
})

test('parse rejects invalid z32 encoding', (t) => {
  t.exception(() => parse('hs_!!!not-valid-z32!!!'), /Invalid encoding/)
})

test('parse rejects payloads of wrong length', (t) => {
  const tooShort = 'hs_' + z32.encode(b4a.alloc(10))
  const tooLong = 'hs_' + z32.encode(b4a.alloc(100))
  const empty = 'hs_' + z32.encode(b4a.alloc(0))

  t.exception(() => parse(tooShort), /Invalid v1 invite length/)
  t.exception(() => parse(tooLong), /Invalid v1 invite length/)
  t.exception(() => parse(empty), /Invalid v1 invite length/)
})

test('parse rejects unsupported version byte', (t) => {
  const out = generate(FIXED_SEED_HEX)
  const buf = z32.decode(out.invite.slice(3))
  buf[0] = 2

  t.exception(() => parse('hs_' + z32.encode(buf)), /Unsupported invite version/)
})

test('parse rejects a tampered publicKey', (t) => {
  const out = generate(FIXED_SEED_HEX)
  const buf = z32.decode(out.invite.slice(3))
  buf[1] ^= 0xff // flip a byte inside publicKey

  t.exception(() => parse('hs_' + z32.encode(buf)), /Checksum mismatch/)
})

test('parse rejects a tampered capability', (t) => {
  const out = generate(FIXED_SEED_HEX)
  const buf = z32.decode(out.invite.slice(3))
  buf[40] ^= 0xff // flip a byte inside capability

  t.exception(() => parse('hs_' + z32.encode(buf)), /Checksum mismatch/)
})

test('parse rejects a tampered checksum', (t) => {
  const out = generate(FIXED_SEED_HEX)
  const buf = z32.decode(out.invite.slice(3))
  buf[65] ^= 0xff // flip a byte inside checksum

  t.exception(() => parse('hs_' + z32.encode(buf)), /Checksum mismatch/)
})

test('parsed publicKey matches keyPair from generate across random seeds', (t) => {
  for (let i = 0; i < 16; i++) {
    const out = generate()
    const parsed = parse(out.invite)
    t.alike(parsed.publicKey, out.keyPair.publicKey)
    t.alike(parsed.capability, out.capability)
  }
})
