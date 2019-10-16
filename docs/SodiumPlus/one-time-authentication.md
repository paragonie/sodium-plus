## One-time authentication

> **See also**: [Libsodium's documentation on its one-time authentication features](https://download.libsodium.org/doc/advanced/poly1305).

### crypto_onetimeauth

Get an authenticator for a message for a given key.

**Important:** In order to be secure, keys must be:

1. Secret.
2. Unpredictable.
3. Unique.

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{CryptographyKey}` key

Return a `Promise` that resolves to a `Buffer`.

### crypto_onetimeauth_verify

Verify an authenticator for a message for a given key.

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{CryptographyKey}` key
2. `{Buffer}` tag

Return a `Promise` that resolves to a `boolean`.

### crypto_onetimeauth_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_auth` API.

### Example for crypto_onetimeauth

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let plaintext = 'Your message goes here';
    let key = await sodium.crypto_onetimeauth_keygen();
    let tag = await sodium.crypto_onetimeauth(plaintext, key);
    console.log(await sodium.crypto_onetimeauth_verify(plaintext, key, tag));
})();
```
