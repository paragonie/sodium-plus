## Shared-key authentication

> **See also**: [Libsodium's documentation on its shared-key authentication features](https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication).

### crypto_auth

Get an authenticator for a message for a given key.

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{CryptographyKey}` key

Return a `Promise` that resolves to a `Buffer`.

### crypto_auth_verify

Verify an authenticator for a message for a given key.

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{CryptographyKey}` key
2. `{Buffer}` mac

Return a `Promise` that resolves to a `boolean`.

### crypto_auth_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_auth` API.

### Example for crypto_auth

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let plaintext = 'Your message goes here';
    let key = await sodium.crypto_auth_keygen();
    let mac = await sodium.crypto_auth(plaintext, key);
    console.log(await sodium.crypto_auth_verify(plaintext, key, mac));
})();
```
