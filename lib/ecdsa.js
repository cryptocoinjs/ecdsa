!function(globals) {
'use strict'

//*** IMPORTS
var BigInteger = null
var ECPointFp = null
var ecparams = null
var secureRandom = null
//*** IMPORTS END

//*** EXPORTS
var ECDSA = {}

if (typeof module !== 'undefined' && module.exports) { //CommonJS
  secureRandom = require('secure-random') //same name for both
  ECPointFp = require('ecurve').ECPointFp
  ecparams = require('ecurve-names')('secp256k1')
  BigInteger = require('bigi')
  module.exports = ECDSA
} else {
  BigInteger = globals.BigInteger
  secureRandom = globals.secureRandom
  ECPointFp = globals.ECCurveFp.ECPointFp
  ecparams = globals.getSECCurveByName('secp256k1')
  globals.ECDSA = ECDSA
}



//var SecureRandom = require('./jsbn/rng');
//var rng = new SecureRandom();
var rng = { //for cryptocoin-bigint AKA jsbn
  nextBytes: function(arr) {
    var byteArr = secureRandom(arr.length)
    for (var i = 0; i < byteArr.length; ++i) 
      arr[i] = byteArr[i]
  }
}


var P_OVER_FOUR = null;

function implShamirsTrick(P, k, Q, l)
{
  var m = Math.max(k.bitLength(), l.bitLength());
  var Z = P.add2D(Q);
  var R = P.curve.getInfinity();

  for (var i = m - 1; i >= 0; --i) {
    R = R.twice2D();

    R.z = BigInteger.ONE;

    if (k.testBit(i)) {
      if (l.testBit(i)) {
        R = R.add2D(Z);
      } else {
        R = R.add2D(P);
      }
    } else {
      if (l.testBit(i)) {
        R = R.add2D(Q);
      }
    }
  }

  return R;
};

  
ECDSA.getBigRandom = function (limit) {
    return new BigInteger(limit.bitLength(), rng)
      .mod(limit.subtract(BigInteger.ONE))
      .add(BigInteger.ONE)
    ;
}
  
ECDSA.sign = function (hash, priv) {
    var d = priv;
    var n = ecparams.getN();
    var e = BigInteger.fromByteArrayUnsigned(hash);

    do {
      var k = ECDSA.getBigRandom(n);
      var G = ecparams.getG();
      var Q = G.multiply(k);
      var r = Q.getX().toBigInteger().mod(n);
    } while (r.compareTo(BigInteger.ZERO) <= 0);

    var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

    return ECDSA.serializeSig(r, s);
}

ECDSA.verify = function (hash, sig, pubkey) {
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
    } else if (Array.isArray(pubkey)) {
      Q = ECPointFp.decodeFrom(ecparams.getCurve(), pubkey);
    } else {
      throw new Error("Invalid format for pubkey value, must be byte array or ECPointFp");
    }
    var e = BigInteger.fromByteArrayUnsigned(hash);

    return ECDSA.verifyRaw(e, r, s, Q);
}

ECDSA.verifyRaw = function (e, r, s, Q) {
    var n = ecparams.getN();
    var G = ecparams.getG();

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

  /**
   * Serialize a signature into DER format.
   *
   * Takes two BigIntegers representing r and s and returns a byte array.
   */
ECDSA.serializeSig = function (r, s) {
    var rBa = r.toByteArraySigned();
    var sBa = s.toByteArraySigned();

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
   * Parses a byte array containing a DER-encoded signature.
   *
   * This function will return an object of the form:
   *
   * {
   *   r: BigInteger,
   *   s: BigInteger
   * }
   */
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

ECDSA.parseSigCompact = function (sig) {
    if (sig.length !== 65) {
      throw new Error("Signature has the wrong length");
    }

    // Signature is prefixed with a type byte storing three bits of
    // information.
    var i = sig[0] - 27;
    if (i < 0 || i > 7) {
      throw new Error("Invalid signature type");
    }

    var n = ecparams.getN();
    var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
    var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

    return {r: r, s: s, i: i};
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
ECDSA.calcPubkeyRecoveryParam = function (address, r, s, hash)
  {
    for (var i = 0; i < 4; i++) {
      var pubkey = ECDSA.recoverPubKey(r, s, hash, i);
      if (pubkey.getBitcoinAddress().toString() == address) {
        return i;
      }
    }

    throw new Error("Unable to find valid recovery factor");
  }



}(this);
