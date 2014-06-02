var BigInteger = require('bigi');
var secureRandom = require('secure-random');

var sha256 = require('sha256');
var ecurve = require('ecurve')
var ecparams = ecurve.getECParams('secp256k1')

var ECDSA = require('../');

require('terst')

describe('ECDSA()', function() {
  it('should create the ecdsa object with the proper curve', function() {
    var ecdsa = new ECDSA(ecparams);
    EQ (ecdsa.ecparams.g.toString(16), ecparams.g.toString(16));
    EQ (ecdsa.ecparams.n.toString(16), ecparams.n.toString(16));
    EQ (ecdsa.ecparams.h.toString(16), ecparams.h.toString(16));
  })
})

describe('- verify()', function() {
  describe('> when public key is NOT compressed', function() {
    it('should verify the signature', function() {
      var randArr = secureRandom(32, {array: true});
      var privKey = BigInteger.fromByteArrayUnsigned(randArr);
      var ecdsa = new ECDSA(ecparams);
      //var privKey = ecdsa.getBigRandom(ecparams.getN())
      var pubPoint = ecparams.g.multiply(privKey)
      var pubKey = pubPoint.getEncoded(false) //true => compressed
      var msg = "hello world!"
      var shaMsg = sha256(msg)
      var signature = ecdsa.sign(shaMsg, privKey)
      var isValid = ecdsa.verify(shaMsg, signature, pubKey)
      T (isValid)
    })
  })

  describe('> when public key is compressed', function() {
    it('should verify the signature', function() {
      var randArr = secureRandom(32, {array: true})
      var privKey = BigInteger.fromByteArrayUnsigned(randArr)
      var ecdsa = new ECDSA(ecparams);
      //var privKey = ecdsa.getBigRandom(ecparams.getN())
      var pubPoint = ecparams.g.multiply(privKey)
      var pubKey = pubPoint.getEncoded(true) //true => compressed
      var msg = "hello world!"
      var shaMsg = sha256(msg)
      var signature = ecdsa.sign(shaMsg, privKey)
      var isValid = ecdsa.verify(shaMsg, signature, pubKey)
      T (isValid)
    })
  })
})

describe('+ verify()', function() {
  describe('> when public key is NOT compressed', function() {
    it('should verify the signature', function() {
      var randArr = secureRandom(32, {array: true});
      var privKey = BigInteger.fromByteArrayUnsigned(randArr);
      
      ECDSA.ecparams = ecparams;
      //var privKey = ecdsa.getBigRandom(ecparams.getN())
      var pubPoint = ecparams.g.multiply(privKey)
      var pubKey = pubPoint.getEncoded(false) //true => compressed
      var msg = "hello world!"
      var shaMsg = sha256(msg)
      var signature = ECDSA.sign(shaMsg, privKey)
      var isValid = ECDSA.verify(shaMsg, signature, pubKey)
      T (isValid)
    })
  })

  describe('> when public key is compressed', function() {
    it('should verify the signature', function() {
      var randArr = secureRandom(32, {array: true})
      var privKey = BigInteger.fromByteArrayUnsigned(randArr)
      //var privKey = ecdsa.getBigRandom(ecparams.getN())
      var pubPoint = ecparams.g.multiply(privKey)
      var pubKey = pubPoint.getEncoded(true) //true => compressed
      var msg = "hello world!"
      var shaMsg = sha256(msg)
      var signature = ECDSA.sign(shaMsg, privKey)
      var isValid = ECDSA.verify(shaMsg, signature, pubKey)
      T (isValid)
    })
  })
})


