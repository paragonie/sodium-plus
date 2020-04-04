const { describe, it } = require('mocha');
const { expect } = require('chai');
const { SodiumPlus } = require('../index');
const VERBOSE = false;

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

describe('SodiumPlus', () => {
    it('crypto_pwhash', async function() {
        this.timeout(0);
        if (!sodium) sodium = await SodiumPlus.auto();
        let password = 'correct horse battery staple';
        let salt = Buffer.from('808182838485868788898a8b8c8d8e8f', 'hex');
        let hashed = await sodium.crypto_pwhash(
            16,
            password,
            salt,
            sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        expect(hashed.toString('hex')).to.be.equals('720f95400220748a811bca9b8cff5d6e');
    });
});
