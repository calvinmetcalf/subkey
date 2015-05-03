subkey
===

Create signatures based on an RSA key, but using a ed25519 session key to avoid
signature oracle issues.  Uses [elliptic](https://github.com/indutny/elliptic) for ECDSA.

API
===
```js
var subkey = require('subkey');

var signature = subkey.sign(yourPrivateKey, 'your message');

subkey.verify(yourPublicKey, signature, 'your message');
// returns true

subkey.verify(yourPublicKey, signature, 'not your message');
// returns false
```

The first time you sign with an RSA key an ed25519 key is created and signed with your RSA key.  This key is used to sign all messaged and they public key, and the key signature are included with the message signature each time you sign something. This ephemeral subkey is only saved in memory and will not be saved.

When verifying, the first time a key, session key, and session key signature combination is seen it is verified and will fail to verify if the session key in the signature does not match the RSA key.  It then verifies against session key returning true or false depending on whether it verifies.
