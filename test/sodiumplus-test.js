const assert = require('assert');
const { describe, it } = require('mocha');
const { expect } = require('chai');
const { CryptographyKey, SodiumPlus, X25519PublicKey, X25519SecretKey } = require('../index');
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
    it('SodiumPlus.add()', async () => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let foo = Buffer.from('ed000000', 'hex');
        let bar = Buffer.from('01000000', 'hex');
        let baz = await sodium.add(foo, bar);
        expect(baz.toString('hex')).to.be.equals('ee000000');

        bar = Buffer.from('ff000000', 'hex');
        baz = await sodium.add(baz, bar);
        expect(baz.toString('hex')).to.be.equals('ed010000');

        foo = Buffer.from('ffffffff', 'hex');
        bar = Buffer.from('01000000', 'hex');
        baz = await sodium.add(foo, bar);
        expect(baz.toString('hex')).to.be.equals('00000000');
        bar = Buffer.from('02000000', 'hex');
        baz = await sodium.add(foo, bar);
        expect(baz.toString('hex')).to.be.equals('01000000');
    });

    it('SodiumPlus.crypto_aead_xchacha20poly1305_ietf_*', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let plaintext = Buffer.from(
            '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
            '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
            '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
            '637265656e20776f756c642062652069742e',
            'hex'
        );
        let assocData = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
        let nonce = Buffer.from('404142434445464748494a4b4c4d4e4f5051525354555657', 'hex');
        let key = CryptographyKey.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');

        let ciphertext = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, nonce, key, assocData);

        let expected = 'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
            '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
            '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
            '21f9664c97637da9768812f615c68b13b52e' +
            'c0875924c1c7987947deafd8780acf49';
        expect(ciphertext.toString('hex')).to.be.equals(expected);

        let decrypted = await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, nonce, key, assocData);
        expect(decrypted.toString('hex')).to.be.equals(plaintext.toString('hex'));

        let randomKey = await sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
        assert(randomKey instanceof CryptographyKey);

        let ciphertext2 = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, nonce, randomKey);
        decrypted = await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext2, nonce, randomKey);
        expect(decrypted.toString('hex')).to.be.equals(plaintext.toString('hex'));
        expect(ciphertext.toString('hex')).to.not.equals(ciphertext2.toString('hex'));
    });

    it('SodiumPlus.crypto_auth', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let key = await sodium.crypto_auth_keygen();
        let message = 'Science, math, technology, engineering, and compassion for others.';
        let mac = await sodium.crypto_auth(message, key);
        assert(await sodium.crypto_auth_verify(message, key, mac) === true);
    });

    it('SodiumPlus.crypto_box', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let plaintext = 'Science, math, technology, engineering, and compassion for others.';

        let aliceKeypair = await sodium.crypto_box_keypair();
        let aliceSecret = await sodium.crypto_box_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_box_publickey(aliceKeypair);
        let bobKeypair = await sodium.crypto_box_keypair();
        let bobSecret = await sodium.crypto_box_secretkey(bobKeypair);
        let bobPublic = await sodium.crypto_box_publickey(bobKeypair);

        let nonce = await sodium.randombytes_buf(24);

        let ciphertext = await sodium.crypto_box(plaintext, nonce, aliceSecret, bobPublic);
        let decrypted = await sodium.crypto_box_open(ciphertext, nonce, bobSecret, alicePublic);
        expect(decrypted.toString('hex')).to.be.equals(Buffer.from(plaintext).toString('hex'));
    });

    it('SodiumPlus.crypto_box_seal', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let plaintext = 'Science, math, technology, engineering, and compassion for others.';

        let aliceKeypair = await sodium.crypto_box_keypair();
        let aliceSecret = await sodium.crypto_box_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_box_publickey(aliceKeypair);
        assert(aliceSecret instanceof X25519SecretKey);
        assert(alicePublic instanceof X25519PublicKey);

        let ciphertext = await sodium.crypto_box_seal(plaintext, alicePublic);
        let decrypted = await sodium.crypto_box_seal_open(ciphertext, alicePublic, aliceSecret);
        expect(decrypted.toString('hex')).to.be.equals(Buffer.from(plaintext).toString('hex'));
    });

    it('SodiumPlus.crypto_generichash', async() => {
        let message = 'Science, math, technology, engineering, and compassion for others.';
        let piece1 = message.slice(0, 16);
        let piece2 = message.slice(16);

        let hash1 = await sodium.crypto_generichash(message);
        expect(hash1.toString('hex')).to.be.equals('47c1fdbde32b30b9c54dd47cf88ba92d2d05df1265e342c9563ed56aee84ab02');

        let state = await sodium.crypto_generichash_init();
        await sodium.crypto_generichash_update(state, piece1);
        await sodium.crypto_generichash_update(state, piece2);
        let hash2 = await sodium.crypto_generichash_final(state);
        expect(hash1.toString('hex')).to.be.equals(hash2.toString('hex'));

        let key = await sodium.crypto_generichash_keygen();
        hash1 = await sodium.crypto_generichash(message, key);
        state = await sodium.crypto_generichash_init(key);
        await sodium.crypto_generichash_update(state, piece1);
        await sodium.crypto_generichash_update(state, piece2);
        hash2 = await sodium.crypto_generichash_final(state);
        expect(hash1.toString('hex')).to.be.equals(hash2.toString('hex'));

    });

    it('SodiumPlus.crypto_scalarmult', async() => {
        let aliceKeypair = await sodium.crypto_box_keypair();
        let aliceSecret = await sodium.crypto_box_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_box_publickey(aliceKeypair);
        assert(aliceSecret instanceof X25519SecretKey);
        assert(alicePublic instanceof X25519PublicKey);

        // crypto_scalarmult_base test:
        let testPublic = await sodium.crypto_scalarmult_base(aliceSecret);
        expect(testPublic.getBuffer().toString('hex')).to.be.equals(alicePublic.getBuffer().toString('hex'));

        // crypto_scalarmult test:
        let bobKeypair = await sodium.crypto_box_keypair();
        let bobSecret = await sodium.crypto_box_secretkey(bobKeypair);
        let bobPublic = await sodium.crypto_box_publickey(bobKeypair);

        expect(alicePublic.getBuffer().toString('hex')).to.be.equals(alicePublic.getBuffer().toString('hex'));

        let ab = await sodium.crypto_scalarmult(aliceSecret, bobPublic);
        expect(ab.toString('hex')).to.not.equals('0000000000000000000000000000000000000000000000000000000000000000');
        let ba = await sodium.crypto_scalarmult(bobSecret, alicePublic);
        expect(ba.toString('hex')).to.not.equals('0000000000000000000000000000000000000000000000000000000000000000');
        expect(ab.toString('hex')).to.be.equals(ba.toString('hex'));
    });

    it('SodiumPlus.crypto_secretbox', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let plaintext = 'Science, math, technology, engineering, and compassion for others.';

        let key = await sodium.crypto_secretbox_keygen();
        let nonce = await sodium.randombytes_buf(24);

        let ciphertext = await sodium.crypto_secretbox(plaintext, nonce, key);
        let decrypted = await sodium.crypto_secretbox_open(ciphertext, nonce, key);
        expect(decrypted.toString('hex')).to.be.equals(Buffer.from(plaintext).toString('hex'));
    });

    it('SodiumPlus.crypto_shorthash', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let key = CryptographyKey.from('808182838485868788898a8b8c8d8e8f', 'hex');
        let message;
        let hash;

        message = 'This is short input0';
        hash = await sodium.crypto_shorthash(message, key);
        expect(hash.toString('hex')).to.be.equals('ef589fb9ef4196b3');

        message = 'This is short input1';
        hash = await sodium.crypto_shorthash(message, key);
        expect(hash.toString('hex')).to.be.equals('5e8f01039bc53eb7');
    });

    it('SodiumPlus.memzero', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let buf = await sodium.randombytes_buf(16);
        expect(buf.toString('hex')).to.not.equals('00000000000000000000000000000000');
        await sodium.sodium_memzero(buf);
        expect(buf.toString('hex')).to.be.equals('00000000000000000000000000000000');
    });

    it('SodiumPlus.crypto_sign', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let aliceKeypair = await sodium.crypto_sign_keypair();
        let aliceSecret = await sodium.crypto_sign_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_sign_publickey(aliceKeypair);

        let plaintext = 'Science, math, technology, engineering, and compassion for others.';
        let signed = await sodium.crypto_sign(plaintext, aliceSecret);
        let opened = await sodium.crypto_sign_open(signed, alicePublic);
        expect(signed.slice(64).toString('hex')).to.be.equals(opened.toString('hex'));
        expect(opened.toString()).to.be.equals(plaintext);

        let signature = await sodium.crypto_sign_detached(plaintext, aliceSecret);
        let valid = await sodium.crypto_sign_verify_detached(plaintext, alicePublic, signature);
        expect(valid).to.be.equals(true);
    });
});
