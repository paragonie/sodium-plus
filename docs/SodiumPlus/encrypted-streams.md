## Encrypted Streams

> **See also:** [Libsodium's documentation on its encrypted streams feature](https://download.libsodium.org/doc/secret-key_cryptography/secretstream)

### crypto_secretstream_xchacha20poly1305_init_push()

Initialize a stream for streaming encryption.

**Parameters and their respective types**:

1. `{CryptographyKey}` key

Returns a `Promise` that resolves to a [Stream Encryptor object](#stream-encryptor-object)
wrapping backend-specific state in order to restrict direct access to it:

* `LibsodiumWrappers` returns a `number` (a pointer to an internal buffer)
* `SodiumNative` returns a `CryptoSecretstreamXchacha20poly1305StateWrap`
  object

### crypto_secretstream_xchacha20poly1305_init_pull()

Initialize a stream for streaming decryption.

**Parameters and their respective types**:

1. `{CryptographyKey}` key
2. `{Buffer}` header (must be 24 bytes)

Returns a `Promise` that resolves to a [Stream Decryptor object](#stream-decryptor-object)
wrapping backend-specific state in order to restrict direct access to it:

* `LibsodiumWrappers` returns a `number` (a pointer to an internal buffer)
* `SodiumNative` returns a `CryptoSecretstreamXchacha20poly1305StateWrap`
  object

### Stream Encryptor object

[`crypto_secretstream_xchacha20poly1305_init_push`](#crypto_secretstream_xchacha20poly1305_init_push) method
returns a `Promise` that resolves to an object with following properties & methods:

* Property [`header`](#header): a 24-byte header that should be included in the encrypted stream.
* Method [`push`](#push): encrypt some data in a stream.
* Method [`rekey`](#rekey): deterministic re-keying of the internal state.

#### `header`

A 24-byte header that should be included in the encrypted stream.

#### `push`

Encrypt some data in a stream.

**Parameters and their respective types**:

1. `{string|Buffer}` message
1. `{string|Buffer}` (optional) additional associated data
1. `{number}` tag (default = 0, see libsodium docs)

Returns a `Promise` that resolves to a `Buffer` containing the ciphertext.

#### `rekey`

Deterministic re-keying of the internal state.

Returns a `Promise` that resolves to `undefined`. Instead,
the underlying backend-specific `state` is overwritten in-place.

### Stream Decryptor object

[`crypto_secretstream_xchacha20poly1305_init_pull`](#crypto_secretstream_xchacha20poly1305_init_pull) method
returns a `Promise` that resolves to an object with following method:

* Method [`pull`](#pull): decrypt some data in a stream.

#### `pull`

Decrypt some data in a stream.

**Parameters and their respective types**:

1. `{string|Buffer}` ciphertext
1. `{string|Buffer}` (optional) additional associated data
1. `{number}` tag (default = 0, see libsodium docs)

Returns a `Promise` that resolves to a `Buffer` containing
decrypted plaintext.

### crypto_secretstream_xchacha20poly1305_keygen()

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_secretstream` API.

### Example for crypto_secretstream_xchacha20poly1305

```javascript
const fsp = require('fs').promises;
const path = require('path');
const { SodiumPlus } = require('sodium-plus');

let sodium;
(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();

    let key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    let encryptor, decryptor;
    encryptor = await sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

    // Get a test input from the text file.
    let longText = await fsp.readFile(path.join(__dirname, 'encrypted-streams.md'));
    let chunk, readUntil;
    let ciphertext = Buffer.concat([encryptor.header]);

    // How big are our chunks going to be?
    let PUSH_CHUNK_SIZE = await sodium.randombytes_uniform(longText.length - 32) + 32;
    let PULL_CHUNK_SIZE = PUSH_CHUNK_SIZE + sodium.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    // Encryption...
    for (let i = 0; i < longText.length; i += PUSH_CHUNK_SIZE) {
        readUntil = (i + PUSH_CHUNK_SIZE) > longText.length ? longText.length : i + PUSH_CHUNK_SIZE;
        chunk = await encryptor.push(
            longText.slice(i, readUntil)
        );
        ciphertext = Buffer.concat([ciphertext, chunk]);
    }

    decryptor = await sodium.crypto_secretstream_xchacha20poly1305_init_pull(key, ciphertext.slice(0, 24));
    // Decrypt, starting at 24 (after the header already extracted above)
    let decrypted = Buffer.alloc(0);
    for (let i = 24; i < ciphertext.length; i += PULL_CHUNK_SIZE) {
        readUntil = (i + PULL_CHUNK_SIZE) > ciphertext.length ? ciphertext.length : i + PULL_CHUNK_SIZE;
        chunk = await decryptor.pull(
            ciphertext.slice(i, readUntil)
        );
        decrypted = Buffer.concat([decrypted, chunk]);
    }
    console.log(decrypted.toString());
})();
```
