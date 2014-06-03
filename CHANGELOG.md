0.5.0 / 2014-0x-dd
------------------
* added Travis CI support
* added Coveralls support
* upgraded `~ecurve@0.3.2` to `^ecurve@0.6.0`
* removed `ecurve-names` from dev deps
* upgraded `~bigi@0.2.0` to `^bigi@1.1.0`
* removed `sha256` from dev deps
* changed the way the module should be used, old way was very cumbersome

New Way:

```js
var ecdsa = require('ecdsa') //defaults to secp256k1 curve
```

if you want another curve:

```js
var ecdsa = require('ecdsa')('secp256r1')
```

* added `deterministicGenerateK()`, RFC 6979. See: https://github.com/cryptocoinjs/ecdsa/issues/4.
* added `recoverPubKey()` from BitcoinJS
* added `serializeSigCompact()` from BitcoinJS
* changed method signature of `sign(hash, privateKeyBigInteger)` to sign(hash, privateKeyBuffer)`
* `sign()` method now uses low `s` value: See: https://github.com/cryptocoinjs/ecdsa/issues/10
* renamed `calcPubkeyRecoveryParam()` to `calcPubKeyRecoveryParam()`, changed signature
* added Testling support 


0.4.1 / 2014-04-14
------------------
* bugfix: `parseSigCompact()` referencing invalid `ecparams` #6
* bugfix: `verify()` works with compressed keys #9
* add browser tests

0.4.0 / 2014-03-13
------------------
* removed bower / component stuff. Still works with browser, just use `browserify`. Closes #3
* moved from 4 spaces to 2 spaces (Node style)
* made class based so that multiple instantiations can be made with different curves, i.e. not just tied to `secp256k1`. Closes #2 
  BREAKING CHANGE. Set `ECDSA.ecparams` before using `ECDSA`.

* made class level methods so that existing code should work with very little modification
* removed dependency upon `ecurve-names`
* update deps: `secure-random` and `ecurve`. (will eventually removed secure-random)

0.3.0 / 2013-12-08
------------------
* upgraded deps (for `bigi`)

0.2.0 / 2013-12-07
------------------
* moved `recoverPubKey()` to package `eckey`
* added test for `verify()` and `sign()`

0.1.0 / 2013-11-20
------------------
* changed package name 
* removed AMD support


0.0.1 / 2013-11-12
------------------
* initial release