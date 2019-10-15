## General-purpose cryptographic hash

> **See also**: [Libsodium's documentation on its generic hashing features](https://download.libsodium.org/doc/hashing/generic_hashing).

### crypto_generichash

General-purpose cryptographic hash (powered by BLAKE2).

**Parameters and their respective types**:

1. `{Buffer}` message
2. `{CryptographyKey|null}` key (optional)
3. `{number}` output length (optional, defaults to 32)

Returns a `Promise` that resolves to a `Buffer`.

### crypto_generichash_keygen

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
