const assert = require('assert');
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
    it('SodiumPlus.crypto_pwhash_str', async function () {
        this.timeout(0);
        if (!sodium) sodium = await SodiumPlus.auto();
        let password = 'correct horse battery staple';
        let hashed = await sodium.crypto_pwhash_str(
            password,
            sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        assert(hashed);
        assert(await sodium.crypto_pwhash_str_verify(password, hashed));
        assert(await sodium.crypto_pwhash_str_verify('incorrect password', hashed) === false);

        let needs;
        needs = await sodium.crypto_pwhash_str_needs_rehash(
            hashed,
            sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        expect(needs).to.be.equals(false);
        needs = await sodium.crypto_pwhash_str_needs_rehash(
            hashed,
            sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE + 1,
            sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        expect(needs).to.be.equals(true);
        needs = await sodium.crypto_pwhash_str_needs_rehash(
            hashed,
            sodium.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            sodium.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE << 1
        );
        expect(needs).to.be.equals(true);
    });
});