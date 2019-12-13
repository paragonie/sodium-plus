## Utilities

### sodium_bin2hex

Encode data into a hexadecimal string.

**Parameters and their respective types**:

1. `{string|Buffer}` non-hex-encoded input

Returns a `Promise` that resolves to a `string`.

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let buf = await sodium.randombytes_buf(32);

    console.log(await sodium.sodium_bin2hex(buf));
})();
```

### sodium_hex2bin

Decode data from a hexadecimal string to a `Buffer`.

**Parameters and their respective types**:

1. `{string|Buffer}` hex-encoded input

Returns a `Promise` that resolves to a `Buffer`.

```javascript
const { SodiumPlus } = require('sodium-plus');
let sodium;

(async function () {
    if (!sodium) sodium = await SodiumPlus.auto();
    let hex = '491d40c4924ba547d6f0bda9da77a539391decdc';

    console.log(await sodium.sodium_hex2bin(hex));
})();
```
