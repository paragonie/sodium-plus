## Shared-key authenticated encryption

> **See also**: [Libsodium's documentation on its shared-key authenticated encryption features](https://download.libsodium.org/doc/secret-key_cryptography/secretbox).

### crypto_secretbox

Shared-key authenticated encryption.

**Parameters and their respective types**:

1. `{string|Buffer}` Plaintext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer`.

### crypto_secretbox_open

Shared-key authenticated decryption.

**Parameters and their respective types**:

1. `{string|Buffer}` Ciphertext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer`.
Throws a `SodiumError` on decryption failure.

### crypto_secretbox_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_secretbox` API.

### Example for crypto_secretbox

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let plaintext = 'Your message goes here';
    let key = await sodium.crypto_secretbox_keygen();
    let nonce = await sodium.randombytes_buf(24);
    let ciphertext = await sodium.crypto_secretbox(
        plaintext,
        nonce,
        key    
    );

    console.log(ciphertext.toString('hex'));

    let decrypted = await sodium.crypto_secretbox_open(
        ciphertext,
        nonce,
        key
    );

    console.log(decrypted.toString());
})();
```
