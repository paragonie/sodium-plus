## Password-based key derivation

> **See also**: [Libsodium's documentation on Argon2](https://download.libsodium.org/doc/password_hashing/the_argon2i_function).

### crypto_pwhash

Derive a cryptography key from a password and salt.

**Parameters and their respective types**:

1. `{number}` output length
2. `{string|Buffer}` password
3. `{Buffer}` salt (16 bytes)
4. `{number}` opslimit (recommeded minimum: `2`)
5. `{number}` memlimit (recommended mimimum: `67108864` a.k.a. 64MiB)
6. `{number|null}` algorithm (recommended: `this.CRYPTO_PWHASH_ALG_DEFAULT`)

Returns a `Promise` that resolves to a `CryptographyKey`.

### Example for crypto_pwhash

This example is for key derivation. Look [below](#example-for-crypto_pwhash_str)
for information about password storage/verification.

```javascript

const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    
    let password = 'correct horse battery staple';
    let salt = await sodium.randombytes_buf(16);

    let key = await sodium.crypto_pwhash(
        32,
        password,
        salt,
        sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );
    console.log(key.getBuffer().toString('hex'));
})();
```
