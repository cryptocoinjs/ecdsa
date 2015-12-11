var ecdsa = require('..')
var bigi = require('bigi')
var crypto = require('crypto')
var assert = require('assert')
var G = ecdsa.curve.G

/* global describe, it */

function sha256 (x) { return crypto.createHash('sha256').update(x).digest() }

describe('fuzzy tests for sign/verify', function () {
  it('should always work', function () {
    for (var i = 0; i < 100; i++) {
      var priv = sha256('p' + i + Math.random())
      var pub = G.multiply(bigi.fromBuffer(priv)).getEncoded(Math.random() < 0.5)
      var data = sha256('d' + i + Math.random())

      assert(ecdsa.verify(data, ecdsa.sign(data, priv), pub))
    }
  })
})
