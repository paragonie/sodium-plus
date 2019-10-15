## AEAD

> **See also:** [Libsodium's documentation on its AEAD features](https://download.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).

### crypto_aead_xchacha20poly1305_ietf_decrypt

Decrypt a message (and optional associated data) with XChaCha20-Poly1305.

**Parameters and their respective types**:

1. `{string|Buffer}` Ciphertext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key
4. `{string|Buffer}` assocData 

Returns a `Promise` that resolves to a `Buffer`.
Throws a `SodiumError` on decryption failure.

### crypto_aead_xchacha20poly1305_ietf_encrypt

Encrypt a message (and optional associated data) with XChaCha20-Poly1305.

**Parameters and their respective types**:

1. `{string|Buffer}` Plaintext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key
4. `{string|Buffer}` assocData 

Returns a `Promise` that resolves to a `Buffer`.

### crypto_aead_xchacha20poly1305_ietf_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_aead_xchacha20poly1305_ietf_` API.

### Example for crypto_aead_xchacha20poly1305_ietf_*

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let plaintext = 'Your message goes here';
    let key = await sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    let nonce = await sodium.randombytes_buf(24);
    let ciphertext = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        nonce,
        key    
    );

    console.log(ciphertext.toString('hex'));

    let decrypted = await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext,
        nonce,
        key
    );

    console.log(decrypted.toString());
})();
```