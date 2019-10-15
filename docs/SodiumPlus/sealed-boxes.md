## Sealed boxes

> **See also**: [Libsodium's documentation on its sealed boxes features](https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes).

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