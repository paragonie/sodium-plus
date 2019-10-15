## Password hashing and storage

> **See also**: [Libsodium's documentation on its password hashing features](https://download.libsodium.org/doc/password_hashing).

### crypto_pwhash_str

Get a password hash (in a safe-for-storage format).

**Parameters and their respective types**:

1. `{string|Buffer}` password
2. `{number}` opslimit (recommeded minimum: `2`)
3. `{number}` memlimit (recommended mimimum: `67108864` a.k.a. 64MiB)

Returns a `Promise` that resolves to a `string`.

### crypto_pwhash_str_needs_rehash

Does this password need to be rehashed? (i.e. have the algorithm parameters
we want changed since the hash was generated?)

**Parameters and their respective types**:

1. `{string}` password hash
2. `{number}` opslimit (recommeded minimum: `2`)
3. `{number}` memlimit (recommended mimimum: `67108864` a.k.a. 64MiB)

Returns a `Promise` that resolves to a `boolean`.

### crypto_pwhash_str_verify

Verify a password against a known password hash.

1. `{string|Buffer}` password
2. `{string}` password hash

Returns a `Promise` that resolves to a `boolean`.

### Example for crypto_pwhash_str

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let password = 'correct horse battery staple';
    
    // Generating a password hash
    let pwhash = await sodium.crypto_pwhash_str(
        password,
        sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );
    console.log(pwhash);
    
    // Check that we don't need to rotate hashes
    let stale = await sodium.crypto_pwhash_str_needs_rehash(
        pwhash,
        sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );
    if (stale) {
        console.warn('Password needs to be rehashed');
    }

    // Password validation
    if (await sodium.crypto_pwhash_str_verify(password, pwhash)) {
        console.log("Password valid");
    } else {
        console.error("Incorrect password");
    }
})();
```
