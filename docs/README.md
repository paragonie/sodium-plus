# Sodium-Plus

## Getting Started

You always want to use `SodiumPlus` from within an asynchronous function.

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;
async function myFunction() {
    if (!sodium) sodium = await SodiumPlus.auto();

    // Now you can use sodium.FUNCTION_NAME_HERE()
}
```

## SodiumPlus Methods

### crypto_aead_xchacha20poly1305_ietf_decrypt

Decrypt a message (and optional associated data) with XChaCha20-Poly1305.

**Parameters and their respective types**:

1. `{string|Buffer}` Ciphertext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key
4. `{string|Buffer}` assocData 

Returns a `Promise` that resolves to a `Buffer`.

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

### Example for crypto_auth_*

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
