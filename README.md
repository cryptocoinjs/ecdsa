ecdsa
======

JavaScript component for Elliptical Curve Cryptography signing and verify.


See this article for more details: [bitcoin address](http://procbits.com/2013/08/27/generating-a-bitcoin-address-with-javascript).



Install
-------

    npm install --save ecdsa


Example
-------

```js
var ecparams = require('ecurve-names')('secp256k1')
var ecdsa = require('ecdsa')
var sha256 = require('sha256')
var secureRandom = require('secure-random')
var BigInteger = require('bigi')

var randArr = secureRandom(32, {array: true})
var privKey = BigInteger.fromByteArrayUnsigned(randArr)

//must set curve
var ecdsa = new ECDSA(ecparams);

//or
//ECDSA.ecparams = ecparams;

var pubPoint = ecparams.getG().multiply(privKey)
var pubKey = pubPoint.getEncoded(false) //true => compressed, fails though, must investigate
var msg = "hello world!"
var shaMsg = sha256(msg)
var signature = ecdsa.sign(shaMsg, privKey)
var isValid = ecdsa.verify(shaMsg, signature, pubKey)
console.log(isValid) //true
```


Credits
-------

It's not clear to me if this is based upon Tom Wu's work or Stefen Thomas. 



