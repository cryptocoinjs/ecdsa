ecdsa
======

JavaScript component to Elliptical Curve Cryptography signing and verify.


See this article for more details: [bitcoin address](http://procbits.com/2013/08/27/generating-a-bitcoin-address-with-javascript).



Install
-------

### Node.js/Browserify

    npm install --save ecdsa

### Component

    component install cryptocoinjs/ecdsa


### Bower

    bower install ecdsa


### Script

```html
<script src="/path/to/ecdsa.js"></script>
```


Example
-------

```js
var ecdsa = require('../lib/ecdsa')
  , sha256 = require('sha256')
  , secureRandom = require('secure-random')
  , ecparams = require('ecurve-names')('secp256k1')
  , BigInteger = require('cryptocoin-bigint')

var randArr = secureRandom(32, {array: true})
var privKey = BigInteger.fromByteArrayUnsigned(randArr)
//var privKey = ecdsa.getBigRandom(ecparams.getN())
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



