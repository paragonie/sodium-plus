const { describe, it } = require('mocha');
const { expect } = require('chai');
const { SodiumPlus } = require('../index');
const Util = require('../lib/util');
const VERBOSE = false;
const expectError = require('./async-helper');

let sodium;

(async () => {
    if (!sodium) sodium = await SodiumPlus.auto();
    if (VERBOSE) {
        console.log({
            'libsodium-wrappers': sodium.isLibsodiumWrappers(),
            'sodium-native': sodium.isSodiumNative()
        });
    }
})();

describe('Util', async () => {
    it('toBuffer()', async () => {
        if (!sodium) sodium = await SodiumPlus.auto();

        expect(null).to.be.equal(await Util.toBuffer(null));

        let promised = await Util.toBuffer(sodium.crypto_secretbox_keygen());
        expect(32).to.be.equal(promised.getBuffer().length);
        await expectError(Util.toBuffer(12), 'Invalid type; string or buffer expected');
    });
});
