0.4.0 / 2014-03-13
------------------
* removed bower / component stuff. Still works with browser, just use `browserify`. Closes #3
* moved from 4 spaces to 2 spaces (Node style)
* made class based so that multiple instantiations can be made with different curves, i.e. not just tied to `secp256k1`
* made class level methods so that existing code should work with very little modification
* removed dependency upon `ecurve-names`

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