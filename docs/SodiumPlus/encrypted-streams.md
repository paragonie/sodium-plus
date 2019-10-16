## Encrypted Streams

> **See also:** [[Libsodium's documentation on its encrypted streams feature](https://download.libsodium.org/doc/secret-key_cryptography/secretstream)

### crypto_secretstream_xchacha20poly1305_init_push()

Initialize a stream for streaming encryption.

**Parameters and their respective types**:

1. `{CryptographyKey}` key

Returns a `Promise` that resolves to an `array` with 2 elements:

1. A 24-byte header that should be included in the encrypted stream.
2. A backend-specific `state`:
    * `LibsodiumWrappers` returns a `number` (a pointer to an internal buffer)
    * `SodiumNative` returns a `CryptoSecretstreamXchacha20poly1305StateWrap`
      object

The `{state}` type annotation below refers to one of the backend-specific state 
types.

You'll typically want to use it with list unpacking syntax, like so:

```
[state, header] = await sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
```

### crypto_secretstream_xchacha20poly1305_init_pull()

Initialize a stream for streaming decryption.

**Parameters and their respective types**:

1. `{CryptographyKey}` key
2. `{Buffer}` header (must be 24 bytes)

Returns a `Promise` that resolves to a backend-specific `state`:

* `LibsodiumWrappers` returns a `number` (a pointer to an internal buffer)
* `SodiumNative` returns a `CryptoSecretstreamXchacha20poly1305StateWrap`
  object

The `{state}` type annotation below refers to one of the backend-specific state 
types.

### crypto_secretstream_xchacha20poly1305_push()

Encrypt some data in a stream.

**Parameters and their respective types**:

1. `{state}` state
2. `{string|Buffer}` message
3. `{string|Buffer}` (optional) additional associated data
4. `{number}` tag (default = 0, see libsodium docs)

Returns a `Promise` that resolves to a `Buffer` containing the ciphertext.

### crypto_secretstream_xchacha20poly1305_pull()

Decrypt some data in a stream.

**Parameters and their respective types**:

1. `{state}` state
2. `{string|Buffer}` ciphertext
3. `{string|Buffer}` (optional) additional associated data
4. `{number}` tag (default = 0, see libsodium docs)

Returns a `Promise` that resolves to a `Buffer` containing
decrypted plaintext.

### crypto_secretstream_xchacha20poly1305_keygen()

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_secretstream` API.

### crypto_secretstream_xchacha20poly1305_rekey()

Deterministic re-keying of the internal state.

**Parameters and their respective types**:

1. `{state}` state

Returns a `Promise` that resolves to `undefined`. Instead,
the `state` variable is overwritten in-place.

### Example for crypto_secretstream_xchacha20poly1305

```javascript
const fsp = require('fs').promises;
const path = require('path');
const { SodiumPlus } = require('sodium-plus');

let sodium;
(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();

    let key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    let pushState, pullState, header;
    [pushState, header] = await sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

    // Get a test input from the text file.
    let longText = await fsp.readFile(path.join(__dirname, 'encrypted-streams.md'));
    let chunk, readUntil;
    let ciphertext = Buffer.concat([header]);

    // How big are our chunks going to be?
    let PUSH_CHUNK_SIZE = await sodium.randombytes_uniform(longText.length - 32) + 32;
    let PULL_CHUNK_SIZE = PUSH_CHUNK_SIZE + sodium.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    // Encryption...
    for (let i = 0; i < longText.length; i += PUSH_CHUNK_SIZE) {
        readUntil = (i + PUSH_CHUNK_SIZE) > longText.length ? longText.length : i + PUSH_CHUNK_SIZE;
        chunk = await sodium.crypto_secretstream_xchacha20poly1305_push(
            pushState,
            longText.slice(i, readUntil)
        );
        ciphertext = Buffer.concat([ciphertext, chunk]);
    }

    pullState = await sodium.crypto_secretstream_xchacha20poly1305_init_pull(key, header);
    // Decrypt, starting at 24 (after the header, which we already have)
    let decrypted = Buffer.alloc(0);
    for (let i = 24; i < ciphertext.length; i += PULL_CHUNK_SIZE) {
        readUntil = (i + PULL_CHUNK_SIZE) > ciphertext.length ? ciphertext.length : i + PULL_CHUNK_SIZE;
        chunk = await sodium.crypto_secretstream_xchacha20poly1305_pull(
            pullState,
            ciphertext.slice(i, readUntil)
        );
        decrypted = Buffer.concat([decrypted, chunk]);
    }
    console.log(decrypted.toString());
})();
```
