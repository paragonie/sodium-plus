## Digital signatures

> **See also**: [Libsodium's documentation on its public-key signature features](https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures).

### crypto_sign

> See also: [the detached API](#crypto_sign_detached) below.

Sign a message with Ed25519, returning a signed message (prefixed with the signature).

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{Ed25519SecretKey}` secretKey

Returns a `Promise` that resolves to a `Buffer`.

### crypto_sign_open

Verify a signed message with Ed25519, returning the original message if the signature
is valid.

**Parameters and their respective types**:

1. `{string|Buffer}` signedMessage
2. `{Ed25519SecretKey}` publicKey

Returns a `Promise` that resolves to a `Buffer`.

### crypto_sign_detached

Returns the Ed25519 signature of the message, for the given secret key.

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{Ed25519SecretKey}` secretKey

Returns a `Promise` that resolves to a `Buffer`.

### crypto_sign_verify_detached

Returns true if the Ed25519 signature is valid for a given message and public key.

**Parameters and their respective types**:

1. `{string|Buffer}` message
2. `{Ed25519PublicKey}` publicKey
3. `{Buffer}` signature

Returns a `Promise` that resolves to a `boolean`.

### crypto_sign_keypair

Returns a `Promise` that resolves to a `CryptographyKey` containing a 96-byte
`Buffer`. The first 64 bytes are your Ed25519 secret key, the latter 32 are your
Ed25519 public key.

### crypto_sign_seed_keypair

**Parameters and their respective types**:

1. `{Buffer}` 32 byte seed

Returns a `Promise` that resolves to a `CryptographyKey` containing a 96-byte
`Buffer`. The first 64 bytes are your Ed25519 secret key, the latter 32 are your
Ed25519 public key.

### crypto_sign_publickey

**Parameters and their respective types**:

1. `{CryptographyKey}` (buffer must be 96 bytes long)

Returns a `Promise` that resolves to a `Ed25519PublicKey`.


### crypto_sign_secretkey

**Parameters and their respective types**:

1. `{CryptographyKey}` (buffer must be 96 bytes long)

Returns a `Promise` that resolves to a `Ed25519SecretKey`.

### crypto_sign_ed25519_sk_to_curve25519

Obtain a birationally equivalent X25519 secret key, given an Ed25519 secret key.

**Parameters and their respective types**:

1. `{Ed25519SecretKey}`

Returns a `Promise` that resolves to an `X25519SecretKey`.

### crypto_sign_ed25519_pk_to_curve25519

Obtain a birationally equivalent X25519 public key, given an Ed25519 public key.

**Parameters and their respective types**:

1. `{Ed25519PublicKey}`

Returns a `Promise` that resolves to an `X25519PublicKey`.

### Example for crypto_sign

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let aliceKeypair = await sodium.crypto_sign_keypair();
        let aliceSecret = await sodium.crypto_sign_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_sign_publickey(aliceKeypair);
    
    let message = 'This is something I need to sign publicly.';

    // Detached mode:
    let signature = await sodium.crypto_sign_detached(message, aliceSecret);
    console.log(signature.toString('hex'));
    if (await sodium.crypto_sign_verify_detached(message, alicePublic, signature)) {
        console.log("Signature is valid.");
    } else {
        console.error("Invalid signature!");
    }

    // NaCl (crypto_sign / crypto_sign_open):
    let signed = await sodium.crypto_sign(message, aliceSecret);
    let opened = await sodium.crypto_sign_open(signed, alicePublic);
    console.log(opened.toString());
})();
```
