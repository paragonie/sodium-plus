# Getting Started

You always want to use `SodiumPlus` from within an asynchronous function.

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;
async function myFunction() {
    if (!sodium) sodium = await SodiumPlus.auto();

    // Now you can use sodium.FUNCTION_NAME_HERE()
}
```

When you use `await SodiumPlus.auto()`, this will automatically load in the best
backend available for your platform. This is the recommended way to use SodiumPlus.

If you'd rather use a specific backend, you can do the following:

```javascript
const { SodiumPlus, SodiumUtil, getBackendObject } = require('sodium-plus');
let sodium;
 
async function myFunction() {
    if (!sodium) {
        let backend = getBackendObject('LibsodiumWrappers');
        SodiumUtil.populateConstants(backend);
        sodium = new SodiumPlus(backend);
    }

    // Now you can use sodium.FUNCTION_NAME_HERE()
}
```

To discover what backend you're using at runtime, invoke the `getBackendName()`
method on the `SodiumPlus` object, like so:


```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;
async function whichBackend() {
    if (!sodium) sodium = await SodiumPlus.auto();

    console.log(sodium.getBackendName());
}
```

## CryptographyKey

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

## Sodium-Plus in the Browser

First, download [sodium-plus.min.js](../dist) (or find it on a CDN you trust).

Next, include the following script tags in your web page:

```html5
<script src="sodium-plus.min.js"></script>
<script>
(async function() {
    if (!window.sodium) window.sodium = await SodiumPlus.auto();

    // You can now use 

    // Some example code to ensure it's running
    let random = await sodium.randombytes_buf(32);
    let hash = await sodium.crypto_generichash('hello world');
    console.log({
        'random': random.toString('hex'),
        'hash': hash.toString('hex')
    });
})();
</script>
``` 

You can then use the `sodium` API as documented.
