var ecurve = require('ecurve')
var BigInteger = require('bigi')

var ecdsa = require('../')('secp256r1')


describe('ecdsa exports default', function() {
  it('should contain secp256k1', function() {
    EQ (ecdsa.ecparams.n.toString(16), "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
  })
})