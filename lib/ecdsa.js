var crypto = require('crypto')
var assert = require('assert')

var secureRandom = require('secure-random')
var ecurve = require('ecurve')
var ECPointFp = ecurve.ECPointFp 
var BigInteger = require('bigi')

module.exports = ECDSA

//rng stub, consider removing secureRandom
var rng = {
  nextBytes: function(arr) {
    var byteArr = secureRandom(arr.length)
    for (var i = 0; i < byteArr.length; ++i)
      arr[i] = byteArr[i]
  }
}

function ECDSA(curveName) {
  curveName = curveName || 'secp256k1'
  this.ecparams = ecurve.getECParams(curveName)
}

ECDSA.prototype.sign = function (hash, priv) {
  var d = priv;
  var n = this.ecparams.n;
  var e = BigInteger.fromByteArrayUnsigned(hash);

  do {
    var k = ECDSA.getBigRandom(n); //TODO: replace with RFC6979
    var G = this.ecparams.g;
    var Q = G.multiply(k);
    var r = Q.getX().toBigInteger().mod(n);
  } while (r.compareTo(BigInteger.ZERO) <= 0);

  var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

  return {r: r, s: s}
}

ECDSA.prototype.verify = function (hash, sig, pubkey) {
  var r,s;
  if (Array.isArray(sig)) {
    var obj = ECDSA.parseSig(sig);
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
    Q = ECPointFp.decodeFrom(this.ecparams.curve, pubkey);
  } else {
    throw new Error("Invalid format for pubkey value, must be Buffer or ECPointFp");
  }
  var e = BigInteger.fromByteArrayUnsigned(hash);

  return this.verifyRaw(e, {r: r, s: s}, Q);
}

ECDSA.prototype.verifyRaw = function (e, signature, Q) {
  var r = signature.r, s = signature.s

  var n = this.ecparams.n;
  var G = this.ecparams.g;

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

ECDSA.prototype.parseSigCompact = function (buffer) {
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

// CLASS METHODS

ECDSA.getBigRandom = function (limit) {
  return new BigInteger(limit.bitLength(), rng).mod(limit.subtract(BigInteger.ONE)).add(BigInteger.ONE);
}


ECDSA.parseSig = function (sig) {
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

  /**
   * Serialize a signature into DER format.
   *
   * Takes two BigIntegers representing r and s and returns a byte array.
   */
ECDSA.serializeSig = function (signature) {
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







/**
 * Calculate pubkey extraction parameter.
 *
 * When extracting a pubkey from a signature, we have to
 * distinguish four different cases. Rather than putting this
 * burden on the verifier, Bitcoin includes a 2-bit value with the
 * signature.
 *
 * This function simply tries all four cases and returns the value
 * that resulted in a successful pubkey recovery.
 */
ECDSA.calcPubkeyRecoveryParam = function (address, r, s, hash) { //not even used, called from Message.js in bitcoinjs
  for (var i = 0; i < 4; i++) {
    var pubkey = ECDSA.recoverPubKey(r, s, hash, i);
    if (pubkey.getBitcoinAddress().toString() == address) {
      return i;
    }
  }

  throw new Error("Unable to find valid recovery factor");
}

ECDSA.sign = ECDSA.prototype.sign.bind(ECDSA);
ECDSA.verify = ECDSA.prototype.verify.bind(ECDSA);
ECDSA.verifyRaw = ECDSA.prototype.verifyRaw.bind(ECDSA);
ECDSA.parseSigCompact = ECDSA.prototype.parseSigCompact.bind(ECDSA);


