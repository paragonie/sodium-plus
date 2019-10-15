## Key exchange

> **See also**: [Libsodium's documentation on its key exchange features](https://download.libsodium.org/doc/key_exchange).

### crypto_kx_keypair

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
