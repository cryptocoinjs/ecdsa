var ecurve = require('ecurve')
var BigInteger = require('bigi')

var ecdsa = require('../')()


describe('ecdsa exports default', function() {
  it('should contain secp256k1', function() {
    EQ (ecdsa.ecparams.n.toString(16), "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
  })
})