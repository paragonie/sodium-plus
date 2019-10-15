## Key derivation

> **See also**: [Libsodium's documentation on its key derivation features](https://download.libsodium.org/doc/key_derivation).

### crypto_kdf_derive_from_key

Derive a subkey from a master key.

**Parameters and their respective types**:

1. `{number}` output length (typically you want `32`)
2. `{number}` subkey ID
3. `{string|Buffer}` context (must be a string/buffer of length 8)
4. `{CryptographyKey}` master key

Returns a `Promise` that resolves to a `CryptographyKey`.

### crypto_kdf_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_kdf` API.

### Example for crypto_kdf

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let masterKey = await sodium.crypto_kdf_keygen();
    let context = 'Sodium++';

    let subkey1 = await sodium.crypto_kdf_derive_from_key(32, 1, context, masterKey);
    let subkey2 = await sodium.crypto_kdf_derive_from_key(32, 2, context, masterKey);
    let subkey3 = await sodium.crypto_kdf_derive_from_key(32, 3, context, masterKey);
    
    console.log({
        'master-key': masterKey.getBuffer().toString('hex'),
        'subkey1': subkey1.getBuffer().toString('hex'),
        'subkey2': subkey2.getBuffer().toString('hex'),
        'subkey3': subkey3.getBuffer().toString('hex')
    });
})();
```
