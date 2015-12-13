0.7.0 / 2015-12-13
------------------
- extracted bitcoinjs-lib `ecdsa`. Fixes a number of issues of security issues.

0.6.0 / 2014-09-30
------------------
- dropped alternative curve support, only `secp256k1` for now; if we find we need others in the future we can just grab
them from Git history
- upgraded from `"ecurve": "^0.6.0"`to `"ecurve": "^1.0.0"`

0.5.3 / 2014-07-04
------------------
* bugfix: verify() should treat `hash` as a Buffer and as not a byte array, see #14

0.5.2 / 2014-07-03
------------------
* bugfix: `deterministicGenerateK()` now works with BigInteger instances of other `bigi` installations

0.5.1 / 2014-06-03
------------------
* mistakenly left `secure-random` as a production dependency, moved it to development dep

0.5.0 / 2014-06-02
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
* added `recoverPubKey()` from BitcoinJS / [Daniel Cousens](https://github.com/dcousens)
* added `serializeSigCompact()` from BitcoinJS / [Daniel Cousens](https://github.com/dcousens)
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
