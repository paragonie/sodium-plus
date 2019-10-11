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

### crypto_kx_seedpair

This is functionally identical to [`crypto_box_keypair()`](#crypto_box_keypair).

Returns a `Promise` that resolves to a `CryptographyKey` with 64 bytes.

### crypto_kx_seed_keypair

Generate an X25519 keypair from a seed. Unlike `crypto_kx_seedpair()`, this is
deterministic from your seed.

**Parameters and their respective types**:

1. `{string|Buffer}` seed

Returns a `Promise` that resolves to a `CryptographyKey` with 64 bytes.

### crypto_kx_client_session_keys

Perform a key exchange from the client's perspective.

Returns an array of two CryptographyKey objects:

 * The first is meant for data sent from the server to the client (incoming decryption).
 * The second is meant for data sent from the client to the server (outgoing encryption).

**Parameters and their respective types**:

1. `{X25519PublicKey}` client public key (yours)
2. `{X25519SecretKey}` client secret key (yours)
1. `{X25519PublicKey}` server public key (theirs)

Returns a `Promise` that resolves to an array of two `CryptographyKey` objects.

### crypto_kx_server_session_keys

Perform a key exchange from the server's perspective.

Returns an array of two CryptographyKey objects:

 * The first is meant for data sent from the client to the server (incoming decryption).
 * The second is meant for data sent from the server to the client (outgoing encryption).

**Parameters and their respective types**:

1. `{X25519PublicKey}` server public key (yours)
2. `{X25519SecretKey}` server secret key (yours)
1. `{X25519PublicKey}` client public key (theirs)

Returns a `Promise` that resolves to an array of two `CryptographyKey` objects.

### Example for crypto_kx

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let clientKeypair = await sodium.crypto_box_keypair();
        let clientSecret = await sodium.crypto_box_secretkey(clientKeypair);
        let clientPublic = await sodium.crypto_box_publickey(clientKeypair);
    let serverKeypair = await sodium.crypto_kx_seed_keypair('Your static input goes here');
        let serverSecret = await sodium.crypto_box_secretkey(serverKeypair);
        let serverPublic = await sodium.crypto_box_publickey(serverKeypair);
    let clientIKey, clientOKey, serverIKey, serverOKey;

    [clientIKey, clientOKey] = await sodium.crypto_kx_client_session_keys(
        clientPublic,
        clientSecret,
        serverPublic
    );
    [serverIKey, serverOKey] = await sodium.crypto_kx_server_session_keys(
        serverPublic,
        serverSecret,
        clientPublic
    );

    console.log({
        'client-sees': {
            'incoming': clientIKey.getBuffer().toString('hex'),
            'outgoing': clientOKey.getBuffer().toString('hex')
        },
        'server-sees': {
            'incoming': serverIKey.getBuffer().toString('hex'),
            'outgoing': serverOKey.getBuffer().toString('hex')
        }
    });
})();
```

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

### crypto_scalarmult

Elliptic Curve Diffie-Hellman key exchange over Curve25519.
You probably don't want to ever use this directly.

**Parameters and their respective types**:

1. `{X25519SecretKey}` your secret key
2. `{X25519PublicKey}` their public key

Returns a `Promise` that resolves to a `CryptographyKey`.

### crypto_scalarmult_base

Generate an X25519PublicKey from an X25519SecretKey.

**Parameters and their respective types**:

1. `{X25519SecretKey}` your secret key

Returns a `Promise` that resolves to an `X25519PublicKey`.

### Example for crypto_scalarmult

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
        let bobPublic = await sodium.crypto_scalarmult_base(bobSecret);
    
    let aliceToBob = await sodium.crypto_scalarmult(aliceSecret, bobPublic);
    let bobToAlice = await sodium.crypto_scalarmult(bobSecret, alicePublic);
    console.log({
        'alice-to-bob': aliceToBob.getBuffer().toString('hex'),
        'bob-to-alice': bobToAlice.getBuffer().toString('hex')
    });
})();
```

### crypto_secretbox

Shared-key authenticated encryption.

**Parameters and their respective types**:

1. `{string|Buffer}` Plaintext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer`.

### crypto_secretbox_open

Shared-key authenticated decryption.

**Parameters and their respective types**:

1. `{string|Buffer}` Ciphertext
2. `{string|Buffer}` nonce (must be 24 bytes)
3. `{CryptographyKey}` key

Returns a `Promise` that resolves to a `Buffer`.
Throws a `SodiumError` on decryption failure.

### crypto_secretbox_keygen

Returns a `CryptographyKey` object containing a key appropriate
for the `crypto_secretbox` API.

### Example for crypto_secretbox

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let plaintext = 'Your message goes here';
    let key = await sodium.crypto_secretbox_keygen();
    let nonce = await sodium.randombytes_buf(24);
    let ciphertext = await sodium.crypto_secretbox(
        plaintext,
        nonce,
        key    
    );

    console.log(ciphertext.toString('hex'));

    let decrypted = await sodium.crypto_secretbox_open(
        ciphertext,
        nonce,
        key
    );

    console.log(decrypted.toString());
})();
```

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

> **Warning:** You probably want [`crypto_generichash()`](#crypto_generichash)
> for most use-cases. `crypto_shorthash()` does not offer collision resistance.

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let key = await sodium.crypto_shorthash_keygen();
    let mapped = {};
    mapped['foo'] = await sodium.crypto_shorthash('foo', key);
    mapped['bar'] = await sodium.crypto_shorthash('bar', key);
    mapped['baz'] = await sodium.crypto_shorthash('baz', key);
    console.log(mapped);
})();
```
