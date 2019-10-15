## Scalar multiplication over Curve25519

> **See also**: [Libsodium's documentation on its scalar multiplication features](https://download.libsodium.org/doc/advanced/scalar_multiplication).

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
