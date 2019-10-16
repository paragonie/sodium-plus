## Stream Ciphers

> **See also**: [Libsodium's documentation on its stream cipher features](https://download.libsodium.org/doc/advanced/stream_ciphers/xsalsa20).

### crypto_stream

Obtain an arbitrary-length stream of pseudorandom bytes from a given 
nonce and key.

**Parameters and their respective types**:

1. `{number}` length
2. `{Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer` containing
the pseudorandom bytes.

### crypto_stream_xor

Encrypt a message with a given nonce and key.

> [**Danger: Unauthenticated encryption!**](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken)
> Without a subsequent message authentication strategy, this is vulnerable to
> chosen-ciphertext attacks. Proceed with caution!

**Parameters and their respective types**:

1. `{string|Buffer}` plaintext
2. `{Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer` containing
the encrypted bytes.

### Example for crypto_stream

```javascript
const { SodiumPlus } = require('sodium-plus');

let sodium;
(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let key = await sodium.crypto_stream_keygen();
    let iv = await sodium.randombytes_buf(24);
    let output = await sodium.crypto_stream(64, iv, key);
    console.log(output);

    iv = await sodium.randombytes_buf(24);
    let plaintext = 'This is a secret message';
    let ciphertext = await sodium.crypto_stream_xor(plaintext, iv, key);
    let decrypted =  await sodium.crypto_stream_xor(ciphertext, iv, key);
    console.log(decrypted.toString());
})();
```
