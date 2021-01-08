## Authenticated public-key encryption

> **See also**: [Libsodium's documentation on its public-key authenticated encryption features](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption).

### crypto_box

Public-key authenticated encryption.

**Parameters and their respective types**:

1. `{string|Buffer}` plaintext
2. `{Buffer}` nonce (must be 24 bytes)
3. `{X25519SecretKey}` secret key
4. `{X25519PublicKey}` public key

Returns a `Promise` that resolves to a `Buffer`.

### crypto_box_open

Public-key authenticated encryption.

**Parameters and their respective types**:

1. `{Buffer}` ciphertext
2. `{Buffer}` nonce (must be 24 bytes)
3. `{X25519SecretKey}` secret key
4. `{X25519PublicKey}` public key

Returns a `Promise` that resolves to a `Buffer`.
Throws a `SodiumError` on decryption failure.

### crypto_box_keypair

Returns a `Promise` that resolves to a `CryptographyKey` containing a 64-byte
`Buffer`. The first 32 bytes are your X25519 secret key, the latter 32 are your
X25519 public key.

### crypto_box_keypair_from_secretkey_and_publickey

Combine two X25519 keys (secret, public) into a keypair object.

**Parameters and their respective types**:

1. `{X25519SecretKey}` secret key
2. `{X25519PublicKey}` public key

Returns a `Promise` that resolves to a `CryptographyKey`.

### crypto_box_publickey

**Parameters and their respective types**:

1. `{CryptographyKey}` (buffer must be 64 bytes long)

Returns a `Promise` that resolves to a `X25519PublicKey`.

### crypto_box_secretkey

**Parameters and their respective types**:

1. `{CryptographyKey}` (buffer must be 64 bytes long)

Returns a `Promise` that resolves to a `X25519SecretKey`.

### crypto_box_publickey_from_secretkey

Derive the public key from a given X25519 secret key.

**Parameters and their respective types**:

1. `{X25519SecretKey}`

Returns a `Promise` that resolves to a `X25519PublicKey`.

### Example for crypto_box

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let aliceKeypair = await sodium.crypto_box_keypair();
        let aliceSecret = await sodium.crypto_box_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_box_publickey(aliceKeypair);
    let bobKeypair = await sodium.crypto_box_keypair();
        let bobSecret = await sodium.crypto_box_secretkey(bobKeypair);
        let bobPublic = await sodium.crypto_box_publickey(bobKeypair);
    
    let plaintext = 'Your message goes here';
    let nonce = await sodium.randombytes_buf(24);

    let ciphertext = await sodium.crypto_box(plaintext, nonce, aliceSecret, bobPublic);    
    console.log(ciphertext);

    let decrypted = await sodium.crypto_box_open(ciphertext, nonce, bobSecret, alicePublic);
    console.log(decrypted.toString());
})();
```
