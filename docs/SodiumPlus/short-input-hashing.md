## Short-input hashing

> **See also**: [Libsodium's documentation on its short-input hashing features](https://download.libsodium.org/doc/hashing/short-input_hashing).

### crypto_shorthash

Calculate a fast hash for short inputs.

**Parameters and their respective types**:

1. `{string|Buffer}` input
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer`.

### crypto_shorthash_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_shorthash` API.

### Example for crypto_shorthash

> **Warning:** You probably want [`crypto_generichash()`](general-purpose-cryptographic-hash.md)
> for most use-cases. `crypto_shorthash()` does not offer collision resistance.

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let key = await sodium.crypto_shorthash_keygen();
    let mapped = {};
    mapped['foo'] = (await sodium.crypto_shorthash('foo', key)).toString('hex');
    mapped['bar'] = (await sodium.crypto_shorthash('bar', key)).toString('hex');
    mapped['baz'] = (await sodium.crypto_shorthash('baz', key)).toString('hex');
    console.log(mapped);
})();
```
