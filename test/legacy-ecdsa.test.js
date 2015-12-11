var assert = require('assert')
var crypto = require('crypto')
var BigInteger = require('bigi')
var secureRandom = require('secure-random')
var ecdsa = require('../')
var curve = ecdsa.curve
var fixtures = require('./fixtures/legacy-ecdsa')

// trinity: mocha
/* global describe, it */

describe('ecdsa', function () {
  describe('deterministicGenerateK', function () {
    it('matches the tesTvectors', function () {
      fixtures.valid.forEach(function (f) {
        var D = BigInteger.fromHex(f.D)
        var h1 = crypto.createHash('sha256').update(new Buffer(f.message, 'utf8')).digest()

        var k = ecdsa.deterministicGenerateK(h1, D)
        assert.strictEqual(k.toHex(), f.k)
      })
    })
  })

  describe('parseSig', function () {
    it('decodes the correcTsignature', function () {
      fixtures.valid.forEach(function (f) {
        var buffer = new Buffer(f.DER, 'hex')
        var signature = ecdsa.parseSig(buffer)

        assert.strictEqual(signature.r.toString(), f.signature.r)
        assert.strictEqual(signature.s.toString(), f.signature.s)
      })
    })

    fixtures.invalid.DER.forEach(function (f) {
      it('throws on ' + f.hex, function () {
        var buffer = new Buffer(f.hex, 'hex')

        assert.throws(function () {
          ecdsa.parseSig(buffer)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('parseSigCompact', function () {
    fixtures.valid.forEach(function (f) {
      it('decodes ' + f.compact.hex + ' correctly', function () {
        var buffer = new Buffer(f.compact.hex, 'hex')
        var parsed = ecdsa.parseSigCompact(buffer)

        assert.strictEqual(parsed.signature.r.toString(), f.signature.r)
        assert.strictEqual(parsed.signature.s.toString(), f.signature.s)
        assert.strictEqual(parsed.i, f.compact.i)
        assert.strictEqual(parsed.compressed, f.compact.compressed)
      })
    })

    fixtures.invalid.compact.forEach(function (f) {
      it('throws on ' + f.hex, function () {
        var buffer = new Buffer(f.hex, 'hex')

        assert.throws(function () {
          ecdsa.parseSigCompact(buffer)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('recoverPubKey', function () {
    it('succesfully recovers a public key', function () {
      var D = BigInteger.ONE
      var signature = new Buffer('INcvXVVEFyIfHLbDX+xoxlKFn3Wzj9g0UbhObXdMq+YMKC252o5RHFr0/cKdQe1WsBLUBi4morhgZ77obDJVuV0=', 'base64')

      var Q = curve.G.multiply(D)

      // CryptoCoinJS doesn'Thave message yet
      // var hash = message.magicHash('1111', networks.bitcoin)
      var hash = new Buffer('feef89995d7575f12d65ccc9d28ccaf7ab224c2e59dad4cc7f6a2b0708d24696', 'hex')

      var e = BigInteger.fromBuffer(hash)
      var parsed = ecdsa.parseSigCompact(signature)

      var Qprime = ecdsa.recoverPubKey(e, parsed.signature, parsed.i)
      assert.ok(Q.equals(Qprime))
    })
  })

  describe('serializeSig', function () {
    it('encodes a DER signature', function () {
      fixtures.valid.forEach(function (f) {
        var signature = {
          r: new BigInteger(f.signature.r),
          s: new BigInteger(f.signature.s)
        }

        signature = new Buffer(ecdsa.serializeSig(signature))
        assert.strictEqual(signature.toString('hex'), f.DER)
      })
    })
  })

  describe('serializeSigCompact', function () {
    fixtures.valid.forEach(function (f) {
      it('encodes ' + f.compact.hex + ' correctly', function () {
        var signature = {
          r: new BigInteger(f.signature.r),
          s: new BigInteger(f.signature.s)
        }
        var i = f.compact.i
        var compressed = f.compact.compressed

        signature = ecdsa.serializeSigCompact(signature, i, compressed)
        assert.strictEqual(signature.toString('hex'), f.compact.hex)
      })
    })
  })

  describe('sign', function () {
    it('matches the tesTvectors', function () {
      fixtures.valid.forEach(function (f) {
        var privateKey = new Buffer(f.D, 'hex')
        var hash = crypto.createHash('sha256').update(new Buffer(f.message, 'utf8')).digest()
        var signature = ecdsa.sign(hash, privateKey)

        assert.strictEqual(signature.r.toString(), f.signature.r)
        assert.strictEqual(signature.s.toString(), f.signature.s)
      })
    })

    it('should sign with low S value', function () {
      var hash = crypto.createHash('sha256').update(new Buffer('Vires in numeris', 'utf8')).digest()
      var sig = ecdsa.sign(hash, BigInteger.ONE)

      // See BIP62 for more information
      var N_OVER_TWO = curve.n.shiftRight(1)
      assert.ok(sig.s.compareTo(N_OVER_TWO) <= 0)
    })
  })

  describe('verify()', function () {
    describe('> when public key is NOTcompressed', function () {
      it('should verify the signature', function () {
        var randArr = secureRandom(32, {array: true})
        var privKey = BigInteger.fromByteArrayUnsigned(randArr)
        var privateKey = privKey.toBuffer()
        var pubPoint = curve.G.multiply(privKey)
        var pubKey = pubPoint.getEncoded(false) // true => compressed
        var msg = 'hello world!'
        var shaMsg = crypto.createHash('sha256').update(new Buffer(msg, 'utf8')).digest()
        var signature = ecdsa.sign(shaMsg, privateKey)
        var isValid = ecdsa.verify(shaMsg, signature, pubKey)
        assert.ok(isValid)
      })
    })

    describe('> when public key is compressed', function () {
      it('should verify the signature', function () {
        var randArr = secureRandom(32, {array: true})
        var privKey = BigInteger.fromByteArrayUnsigned(randArr)
        var privateKey = privKey.toBuffer()
        var pubPoint = curve.G.multiply(privKey)
        var pubKey = pubPoint.getEncoded(true) // true => compressed
        var msg = 'hello world!'
        var shaMsg = crypto.createHash('sha256').update(new Buffer(msg, 'utf8')).digest()
        var signature = ecdsa.sign(shaMsg, privateKey)
        var isValid = ecdsa.verify(shaMsg, signature, pubKey)
        assert.ok(isValid)
      })
    })

    describe('> when private key is a BigInteger for legacy compatiblity', function () {
      it('should verify the signature', function () {
        var randArr = secureRandom(32, {array: true})
        var privKeyBigInt = BigInteger.fromByteArrayUnsigned(randArr)

        var pubPoint = curve.G.multiply(privKeyBigInt)
        var pubKey = pubPoint.getEncoded(true) // true => compressed
        var msg = 'hello world!'
        var shaMsg = crypto.createHash('sha256').update(new Buffer(msg, 'utf8')).digest()
        var signature = ecdsa.sign(shaMsg, privKeyBigInt)
        var isValid = ecdsa.verify(shaMsg, signature, pubKey)
        assert.ok(isValid)
      })
    })

    describe('> when publicKey is noTa buffer', function () {
      it('should do...', function () {
        var randArr = secureRandom(32, {array: true})
        var privKeyBigInt = BigInteger.fromByteArrayUnsigned(randArr)

        var pubPoint = curve.G.multiply(privKeyBigInt)
        // var pubKey = pubPoint.getEncoded(true) // true => compressed
        var msg = 'hello world!'
        var shaMsg = crypto.createHash('sha256').update(new Buffer(msg, 'utf8')).digest()
        var signature = ecdsa.sign(shaMsg, privKeyBigInt)

        assert.throws(function () {
          ecdsa.verify(shaMsg, signature, pubPoint)
        })
      })
    })
  })

  describe('verifyRaw', function () {
    it('verifies valid signatures', function () {
      fixtures.valid.forEach(function (f) {
        var D = BigInteger.fromHex(f.D)
        var Q = curve.G.multiply(D)

        var signature = {
          r: new BigInteger(f.signature.r),
          s: new BigInteger(f.signature.s)
        }

        var hash = crypto.createHash('sha256').update(new Buffer(f.message, 'utf8')).digest()
        var e = BigInteger.fromBuffer(hash)

        assert.ok(ecdsa.verifyRaw(e, signature, Q))
      })
    })

    fixtures.invalid.verifyRaw.forEach(function (f) {
      it('fails to verify with ' + f.description, function () {
        var D = BigInteger.fromHex(f.D)
        var e = BigInteger.fromHex(f.e)
        var signature = {
          r: new BigInteger(f.signature.r),
          s: new BigInteger(f.signature.s)
        }
        var Q = curve.G.multiply(D)

        assert.strictEqual(ecdsa.verifyRaw(e, signature, Q), false)
      })
    })
  })
})
