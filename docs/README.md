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

### CryptographyKey

All cryptographic secrets are contained within a `CryptographyKey` object
(or one of its derived classes). You can create and access them like so:

```javascript
const { CryptographyKey } = require('sodium-plus');
let buf = Buffer.alloc(32);
let key = new CryptographyKey(buf);

// If you do this, the internal buffer will not be visible!
console.log(key);
// CryptographyKey {}

// You'll need to do this instead:
console.log(key.getBuffer());
// <Buffer d9 ff 60 6b ff 96 f6 26 05 53 07 39 ef b5 a5 8b 26 0c 72 9e 1b b7 e4 97 fe 09 de 07 86 8a 0c b6>
```

The following classes inherit from `CryptographyKey`:

* `Ed25519PublicKey` -- Ed25519 public key
* `Ed25519SecretKey` -- Ed25519 secret key
* `X25519PublicKey` -- X25519 public key
* `X25519SecretKey` -- X25519 secret key

## SodiumPlus Methods

This describes the methods in the public API for Sodium-Plus.
If you're not sure which method to use, please refer to the
[Libsodium Quick Reference](https://paragonie.com/blog/2017/06/libsodium-quick-reference-quick-comparison-similar-functions-and-which-one-use)
for guidance.

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

### crypto_box_keypair_from_secretkey_and_secretkey

Combine two X25519 keys (secret, public) into a keypair object.

**Parameters and their respective types**:

1. `{X25519SecretKey}` secret key
2. `{X25519PublicKey}` public key

Returns a `Promise` that resolves to a `CryptographyKey`.

### crypto_box_publickey

**Parameters and their respective types**:

1. `{CryptographyKey}` (buffer must be 64 bytes long)

Returns a `Promise` that resolves to a `X25519SecretKey`.


### crypto_box_secretkey

**Parameters and their respective types**:

1. `{CryptographyKey}` (buffer must be 64 bytes long)

Returns a `Promise` that resolves to a `X25519PublicKey`.

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

### crypto_box_seal

Anonymous public-key encryption. (Message integrity is still assured.)

**Parameters and their respective types**:

1. `{string|Buffer}` plaintext
2. `{X25519PublicKey}` public key

Returns a `Promise` that resolves to a `Buffer`.

### crypto_box_seal_open

Anonymous public-key decryption. (Message integrity is still assured.)

**Parameters and their respective types**:

1. `{Buffer}` ciphertext
2. `{X25519PublicKey}` public key
3. `{X25519SecretKey}` secret key

Returns a `Promise` that resolves to a `Buffer`.

### Example for crypto_box_seal

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let aliceKeypair = await sodium.crypto_box_keypair();
        let aliceSecret = await sodium.crypto_box_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_box_publickey(aliceKeypair);
    
    let plaintext = 'Your message goes here';

    let ciphertext = await sodium.crypto_box_seal(plaintext, alicePublic);    
    console.log(ciphertext);

    let decrypted = await sodium.crypto_box_seal_open(ciphertext, alicePublic, aliceSecret);
    console.log(decrypted.toString());
})();
```

### crypto_generichash

General-purpose cryptographic hash (powered by BLAKE2).

**Parameters and their respective types**:

1. `{Buffer}` message
2. `{CryptographyKey|null}` key (optional)
3. `{number}` output length (optional, defaults to 32)

Returns a `Promise` that resolves to a `Buffer`.

### crypto_auth_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_generichash` API.

### crypto_generichash_init

Initialize a BLAKE2 hash context for stream hashing.

**Parameters and their respective types**:

1. `{CryptographyKey|null}` key (optional)
2. `{number}` output length (optional, defaults to 32)

Returns a `Promise` that resolves to... well, that depends on your backend.

* sodium-native returns a `CryptoGenericHashWrap` object.
* libsodium-wrappers returns a number (a buffer's memory address)

### crypto_generichash_update

Update the BLAKE2 hash state with a block of data.

**Parameters and their respective types**:

1. `{*}` hash state (see [crypto_generichash_init()](#crypto_generichash_init))
2. `{string|Buffer}` message chunk

Returns a `Promise` that resolves to `void`. Instead, `state` is updated in-place.

### crypto_generichash_final

Obtain the final BLAKE2 hash output.

**Parameters and their respective types**:

1. `{*}` hash state (see [crypto_generichash_init()](#crypto_generichash_init))
2. `{number}` output length (optional, defaults to 32)

Returns a `Promise` that resolves to a `Buffer`.

### Example for crypto_generichash

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let message = 'Any message can go here';
    let hashed = await sodium.crypto_generichash(message);
    console.log(hashed.toString('hex'));

    let key = await sodium.crypto_generichash_keygen();
    let hash2 = await sodium.crypto_generichash(message, key, 64);
    let state = await sodium.crypto_generichash_init(key, 64);

    await sodium.crypto_generichash_update(state, 'Any message ');
    await sodium.crypto_generichash_update(state, 'can go here');
    let hash3 = await sodium.crypto_generichash_final(state, 64);
    if (!await sodium.sodium_memcmp(hash2, hash3)) {
        throw new Error('Implementation is broken. You should never see this.');
    }
    console.log(hash2.toString('hex'));
})();
```
