
## Randomness

> **See also:** [Libsodium's documentation on its random data features](https://download.libsodium.org/doc/generating_random_data).

### randombytes_buf

Obtain a buffer filled with random bytes.

**Parameters and their respective types**:

1. `{number}` Size of buffer to return

Returns a `Promise` that resolves to a `Buffer`

### randombytes_uniform

Generate an integer between 0 and upperBound (non-inclusive).

For example, randombytes_uniform(10) returns an integer between 0 and 9.

**Parameters and their respective types**:

1. `{number}` Upper bound

Returns a `Promise` that resolves to a `number`.

### Example for randombytes

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    
    let someBuf = await sodium.randombytes_buf(32);
    console.log(someBuf.toString('hex'));

    let someInt = await sodium.randombytes_uniform(65536);
    console.log(someInt);
})();
```
