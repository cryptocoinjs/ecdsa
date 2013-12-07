require('terst')

var ecdsa = require('../lib/ecdsa')
  , sha256 = require('sha256')
  , secureRandom = require('secure-random')
  , ecparams = require('ecurve-names')('secp256k1')
  , BigInteger = require('cryptocoin-bigint')

describe('+ verify()', function() {
  it('should verify the signature', function() {
    var randArr = secureRandom(32, {array: true})
    var privKey = BigInteger.fromByteArrayUnsigned(randArr)
    var pubPoint = ecparams.getG().multiply(privKey)
    var pubKey = pubPoint.getEncoded(true) //true => compressed
    var msg = "hello world!"
    var shaMsg = sha256(msg)
    var signature = ecdsa.sign(shaMsg, privKey)
    var isValid = ecdsa.verify(shaMsg, signature, pubKey)
  })
})


