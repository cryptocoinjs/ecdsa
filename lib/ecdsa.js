var crypto = require('crypto')
var assert = require('assert')

var secureRandom = require('secure-random')
var ecurve = require('ecurve')
var ECPointFp = ecurve.ECPointFp 
var BigInteger = require('bigi')

var util = require('./util')

//this is done so that you can do the following:
// var ecdsa = require('ecdsa') //default secp256k1
// instead of 
// var ecdsa require('ecdsa')() <--- awkward "()" that many would forget
//  ... BUT, if you want another curve ....
// var ecdsa = require('ecdsa')(otherCurve)
//
// most people will use this with secp256k1 which is what most (all?)
// crypto currencies use
module.exports = (function(){
  var _ecparams = ecurve.getECParams('secp256k1')

  function _ecdsa(curveName) {
    if (!curveName)
      _ecparams = ecurve.getECParams('secp256k1')
    else
      _ecparams = ecurve.getECParams(curveName)
    return _ecdsa
  }

  //attach functions
  _ecdsa.calcPubkeyRecoveryParam = calcPubkeyRecoveryParam
  _ecdsa.getBigRandom = getBigRandom
  _ecdsa.parseSig = parseSig
  _ecdsa.parseSigCompact = parseSigCompact
  _ecdsa.serializeSig = serializeSig
  _ecdsa.serializeSigCompact = serializeSigCompact

  //attach ecparams functions, remember, almost everyone will be using secp256k1
  _ecdsa.deterministicGenerateK = function() { var args = [].slice.call(arguments); args.unshift(_ecparams); return deterministicGenerateK.apply(null, args)}
  _ecdsa.recoverPubKey = function() { var args = [].slice.call(arguments); args.unshift(_ecparams); return recoverPubKey.apply(null, args)}
  _ecdsa.sign = function() { var args = [].slice.call(arguments); args.unshift(_ecparams); return sign.apply(null, args)}
  _ecdsa.verify = function() { var args = [].slice.call(arguments); args.unshift(_ecparams); return verify.apply(null, args)}
  _ecdsa.verifyRaw = function() { var args = [].slice.call(arguments); args.unshift(_ecparams); return verifyRaw.apply(null, args)}

  return _ecdsa
})();

//rng stub, consider removing secureRandom
var rng = {
  nextBytes: function(arr) {
    var byteArr = secureRandom(arr.length)
    for (var i = 0; i < byteArr.length; ++i)
      arr[i] = byteArr[i]
  }
}


function calcPubkeyRecoveryParam (address, r, s, hash) { //not even used, called from Message.js in bitcoinjs
  for (var i = 0; i < 4; i++) {
    var pubkey = ecdsa.recoverPubKey(r, s, hash, i);
    if (pubkey.getBitcoinAddress().toString() == address) {
      return i;
    }
  }

  throw new Error("Unable to find valid recovery factor");
}

function deterministicGenerateK(ecparams, hash, D) {
  assert(Buffer.isBuffer(hash), 'Hash must be a Buffer, not ' + hash)
  assert.equal(hash.length, 32, 'Hash must be 256 bit')
  assert(D instanceof BigInteger, 'Private key must be a BigInteger')

  var x = D.toBuffer(32)
  var k = new Buffer(32)
  var v = new Buffer(32)
  k.fill(0)
  v.fill(1)

  k = util.hmacSHA256(Buffer.concat([v, new Buffer([0]), x, hash]), k)
  v = util.hmacSHA256(v, k)

  k = util.hmacSHA256(Buffer.concat([v, new Buffer([1]), x, hash]), k)
  v = util.hmacSHA256(v, k)
  v = util.hmacSHA256(v, k)

  var n = ecparams.n
  var kB = BigInteger.fromBuffer(v).mod(n)
  assert(kB.compareTo(BigInteger.ONE) > 0, 'Invalid k value')
  assert(kB.compareTo(ecparams.n) < 0, 'Invalid k value')

  return kB
}

function getBigRandom (limit) {
  return new BigInteger(limit.bitLength(), rng).mod(limit.subtract(BigInteger.ONE)).add(BigInteger.ONE);
}

function parseSig (sig) {
  var cursor;
  if (sig[0] != 0x30)
    throw new Error("Signature not a valid DERSequence");

  cursor = 2;
  if (sig[cursor] != 0x02)
    throw new Error("First element in signature must be a DERInteger");;
  var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

  cursor += 2+sig[cursor+1];
  if (sig[cursor] != 0x02)
    throw new Error("Second element in signature must be a DERInteger");
  var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

  cursor += 2+sig[cursor+1];

  //if (cursor != sig.length)
  //  throw new Error("Extra bytes in signature");

  var r = BigInteger.fromByteArrayUnsigned(rBa);
  var s = BigInteger.fromByteArrayUnsigned(sBa);

  return {r: r, s: s};
}

function parseSigCompact (buffer) {
   assert.equal(buffer.length, 65, 'Invalid signature length')
  var i = buffer.readUInt8(0) - 27

  // At most 3 bits
  assert.equal(i, i & 7, 'Invalid signature parameter')
  var compressed = !!(i & 4)

  // Recovery param only
  i = i & 3

  var r = BigInteger.fromBuffer(buffer.slice(1, 33))
  var s = BigInteger.fromBuffer(buffer.slice(33))

  return {
    signature: {
      r: r,
      s: s
    },
    i: i,
    compressed: compressed
  }
}

/**
  * Recover a public key from a signature.
  *
  * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
  * Key Recovery Operation".
  *
  * http://www.secg.org/download/aid-780/sec1-v2.pdf
  */
function recoverPubKey(ecparams, e, signature, i) {
  assert.strictEqual(i & 3, i, 'The recovery param is more than two bits')

  var r = signature.r
  var s = signature.s

  // A set LSB signifies that the y-coordinate is odd
  // By reduction, the y-coordinate is even if it is clear
  var isYEven = !(i & 1)

  // The more significant bit specifies whether we should use the
  // first or second candidate key.
  var isSecondKey = i >> 1

  var n = ecparams.n
  var G = ecparams.g
  var curve = ecparams.curve
  var p = curve.q
  var a = curve.a.toBigInteger()
  var b = curve.b.toBigInteger()

  // We precalculate (p + 1) / 4 where p is the field order
  if (!curve.P_OVER_FOUR) {
    curve.P_OVER_FOUR = p.add(BigInteger.ONE).shiftRight(2)
  }

  // 1.1 Compute x
  var x = isSecondKey ? r.add(n) : r

  // 1.3 Convert x to point
  var alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p)
  var beta = alpha.modPow(curve.P_OVER_FOUR, p)

  // If beta is even, but y isn't, or vice versa, then convert it,
  // otherwise we're done and y == beta.
  var y = (beta.isEven() ^ isYEven) ? p.subtract(beta) : beta

  // 1.4 Check that nR isn't at infinity
  var R = new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y))
  R.validate()

  // 1.5 Compute -e from e
  var eNeg = e.negate().mod(n)

  // 1.6 Compute Q = r^-1 (sR -  eG)
  //             Q = r^-1 (sR + -eG)
  var rInv = r.modInverse(n)

  var Q = R.multiplyTwo(s, G, eNeg).multiply(rInv)
  Q.validate()

  if (!verifyRaw(ecparams, e, signature, Q)) {
    throw new Error("Pubkey recovery unsuccessful")
  }

  return Q
}

function serializeSig (signature) {
  //var rBa = r.toByteArraySigned();
  //var sBa = s.toByteArraySigned();
  var rBa = signature.r.toDERInteger()
  var sBa = signature.s.toDERInteger()


  var sequence = [];
  sequence.push(0x02); // INTEGER
  sequence.push(rBa.length);
  sequence = sequence.concat(rBa);

  sequence.push(0x02); // INTEGER
  sequence.push(sBa.length);
  sequence = sequence.concat(sBa);

  sequence.unshift(sequence.length);
  sequence.unshift(0x30); // SEQUENCE

  return sequence;
}

function serializeSigCompact(signature, i, compressed) {
  if (compressed) {
    i += 4
  }

  i += 27

  var buffer = new Buffer(65)
  buffer.writeUInt8(i, 0)

  signature.r.toBuffer(32).copy(buffer, 1)
  signature.s.toBuffer(32).copy(buffer, 33)

  return buffer
}

function sign (ecparams, hash, priv) {
  var d = priv;
  var n = ecparams.n;
  var e = BigInteger.fromByteArrayUnsigned(hash);

  do {
    var k = getBigRandom(n); //TODO: replace with RFC6979
    var G = ecparams.g;
    var Q = G.multiply(k);
    var r = Q.getX().toBigInteger().mod(n);
  } while (r.compareTo(BigInteger.ZERO) <= 0);

  var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

  return {r: r, s: s}
}

function verify (ecparams, hash, sig, pubkey) {
  var r,s;
  if (Array.isArray(sig)) {
    var obj = ecdsa.parseSig(sig);
    r = obj.r;
    s = obj.s;
  } else if ("object" === typeof sig && sig.r && sig.s) {
    r = sig.r;
    s = sig.s;
  } else {
    throw new Error("Invalid value for signature");
  }

  var Q;
  if (pubkey instanceof ECPointFp) {
    Q = pubkey;
  } else if (Buffer.isBuffer(pubkey)) {
    Q = ECPointFp.decodeFrom(ecparams.curve, pubkey);
  } else {
    throw new Error("Invalid format for pubkey value, must be Buffer or ECPointFp");
  }
  var e = BigInteger.fromByteArrayUnsigned(hash);

  return verifyRaw(ecparams, e, {r: r, s: s}, Q);
}

function verifyRaw (ecparams, e, signature, Q) {
  var r = signature.r, s = signature.s

  var n = ecparams.n;
  var G = ecparams.g;

  if (r.compareTo(BigInteger.ONE) < 0 ||
      r.compareTo(n) >= 0)
    return false;

  if (s.compareTo(BigInteger.ONE) < 0 ||
      s.compareTo(n) >= 0)
    return false;

  var c = s.modInverse(n);

  var u1 = e.multiply(c).mod(n);
  var u2 = r.multiply(c).mod(n);

  // TODO(!!!): For some reason Shamir's trick isn't working with
  // signed message verification!? Probably an implementation
  // error!
  //var point = implShamirsTrick(G, u1, Q, u2);
  var point = G.multiply(u1).add(Q.multiply(u2));

  var v = point.getX().toBigInteger().mod(n);

  return v.equals(r);
}

