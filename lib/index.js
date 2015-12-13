var ecdsa = require('./ecdsa')
var ecsignature = require('./ecsignature')

var exp = {}

Object.keys(ecdsa).forEach(function (fnName) {
  exp[fnName] = ecdsa[fnName]
})

exp.ECSignature = ecsignature

module.exports = exp
