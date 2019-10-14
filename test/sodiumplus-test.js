const assert = require('assert');
const fsp = require('fs').promises;
const path = require('path');
const { describe, it } = require('mocha');
const { expect } = require('chai');
const { CryptographyKey, SodiumPlus, X25519PublicKey, X25519SecretKey } = require('../index');
const Util = require('../lib/util');
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
    it('SodiumPlus.CONSTANTS', async () => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let dummy = Util.populateConstants({});
        for (let val in dummy) {
            expect(sodium.backend[val]).to.be.equals(dummy[val]);
            expect(sodium[val]).to.be.equals(dummy[val]);
        }
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

    it('SodiumPlus.crypto_kdf', async function() {
        if (!sodium) sodium = await SodiumPlus.auto();
        let subkey, expected;
        let key = CryptographyKey.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
        let context = 'NaClTest';
        subkey = await sodium.crypto_kdf_derive_from_key(32, 1, context, key);
        expected = 'bce6fcf118cac2691bb23975a63dfac02282c1cd5de6ab9febcbb0ec4348181b';
        expect(subkey.toString('hex')).to.be.equals(expected);

        subkey = await sodium.crypto_kdf_derive_from_key(32, 2, context, key);
        expected = '877cf1c1a2da9b900c79464acebc3731ed4ebe326a7951911639821d09dc6dda';
        expect(subkey.toString('hex')).to.be.equals(expected);

        let key2 = await sodium.crypto_kdf_keygen();
        let subkey2 = await sodium.crypto_kdf_derive_from_key(32, 1, context, key2);
        expect(subkey2.toString('hex')).to.not.equals(key2.toString('hex'));
        expect(subkey2.toString('hex')).to.not.equals(subkey.toString('hex'));
    });

    it('SodiumPlus.crypto_kx', async function() {
        if (!sodium) sodium = await SodiumPlus.auto();
        let clientKeys = await sodium.crypto_kx_keypair();
            let clientSecret = await sodium.crypto_box_secretkey(clientKeys);
            let clientPublic = await sodium.crypto_box_publickey(clientKeys);
        let seed = 'Unit test static key seed goes here. Nothing too complicated. No randomness needed, really.';
        let serverKeys = await sodium.crypto_kx_seed_keypair(seed);
            let serverSecret = await sodium.crypto_box_secretkey(serverKeys);
            let serverPublic = await sodium.crypto_box_publickey(serverKeys);
        let clientRx, clientTx, serverRx, serverTx;

        [clientRx, clientTx] = await sodium.crypto_kx_client_session_keys(clientPublic, clientSecret, serverPublic);
        [serverRx, serverTx] = await sodium.crypto_kx_server_session_keys(serverPublic, serverSecret, clientPublic);

        expect(clientRx.toString('hex')).to.be.equals(serverTx.toString('hex'));
        expect(clientTx.toString('hex')).to.be.equals(serverRx.toString('hex'));
    });

    it('SodiumPlus.crypto_onetimeauth', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let key = await sodium.crypto_onetimeauth_keygen();
        let plaintext = 'Science, math, technology, engineering, and compassion for others.';
        let tag = await sodium.crypto_onetimeauth(plaintext, key);
        assert(await sodium.crypto_onetimeauth_verify(plaintext, key, tag));
        assert((await sodium.crypto_onetimeauth_verify(plaintext + ' extra', key, tag)) === false);

        let msg = Buffer.alloc(32, 0);
        key = CryptographyKey.from('746869732069732033322d62797465206b657920666f7220506f6c7931333035', 'hex');
        tag = await sodium.crypto_onetimeauth(msg, key);
        expect(tag.toString('hex')).to.be.equals('49ec78090e481ec6c26b33b91ccc0307');
        assert(await sodium.crypto_onetimeauth_verify(msg, key, tag));
    });

    it('SodiumPlus.crypto_pwhash', async function() {
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

    it('SodiumPlus.crypto_pwhash_str', async function() {
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

    it('SodiumPlus.crypto_secretstream_xchacha20poly1305', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();

        let key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
        let pushState, pullState, header;
        [pushState, header] = await sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
        pullState = await sodium.crypto_secretstream_xchacha20poly1305_init_pull(key, header);

        // Get a test input from the text file.
        let longText = await fsp.readFile(path.join(__dirname, 'longtext.md'));
        let chunk, readUntil;
        let ciphertext = Buffer.concat([header]);

        // How big are our chunks going to be?
        let PUSH_CHUNK_SIZE = await sodium.randombytes_uniform(longText.length - 32) + 32;
        let PULL_CHUNK_SIZE = PUSH_CHUNK_SIZE + sodium.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        // Encrypt
        for (let i = 0; i < longText.length; i += PUSH_CHUNK_SIZE) {
            readUntil = (i + PUSH_CHUNK_SIZE) > longText.length ? longText.length : i + PUSH_CHUNK_SIZE;
            chunk = await sodium.crypto_secretstream_xchacha20poly1305_push(
                pushState,
                longText.slice(i, readUntil)
            );
            ciphertext = Buffer.concat([ciphertext, chunk]);
        }
        expect(ciphertext.slice(0, 24).toString('hex')).to.be
            .equals(header.toString('hex'));

        // Decrypt, starting at 24 (after the header, which we already have)
        let decrypted = Buffer.alloc(0);
        for (let i = 24; i < ciphertext.length; i += PULL_CHUNK_SIZE) {
            readUntil = (i + PULL_CHUNK_SIZE) > ciphertext.length ? ciphertext.length : i + PULL_CHUNK_SIZE;
            chunk = await sodium.crypto_secretstream_xchacha20poly1305_pull(
                pullState,
                ciphertext.slice(i, readUntil)
            );
            decrypted = Buffer.concat([decrypted, chunk]);
        }
        expect(decrypted.toString('hex')).to.be.equals(longText.toString('hex'));
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
        let invalid = await sodium.crypto_sign_verify_detached(plaintext + ' extra', alicePublic, signature);
        expect(invalid).to.be.equals(false);
    });

    it('SodiumPlus.crypto_sign_ed25519_to_curve25519', async function () {
        this.timeout(0);
        if (!sodium) sodium = await SodiumPlus.auto();

        let aliceKeypair = CryptographyKey.from(
            '411a2c2227d2a799ebae0ed94417d8e8ed1ca9b0a9d5f4cd743cc52d961e94e2' +
            'da49154c9e700b754199df7974e9fa4ee4b6ebbc71f89d8d8938335ea4a1409d' +
            'da49154c9e700b754199df7974e9fa4ee4b6ebbc71f89d8d8938335ea4a1409d', 'hex');
        let aliceSecret = await sodium.crypto_sign_secretkey(aliceKeypair);
        let alicePublic = await sodium.crypto_sign_publickey(aliceKeypair);

        let ecdhSecret = await sodium.crypto_sign_ed25519_sk_to_curve25519(aliceSecret);
        expect(ecdhSecret.toString('hex')).to.be
            .equals('60c783b8d1674b7081b72a105b55872502825d4ec638028152e085b54705ad7e');
        let ecdhPublic = await sodium.crypto_sign_ed25519_pk_to_curve25519(alicePublic);
        expect(ecdhPublic.toString('hex')).to.be
            .equals('5a791d07cfb39060c8e9b641b6a915a3126cd14ddc243a9928c490c8e1f59e7c');
    });

    it('SodiumPlus.crypto_stream', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        let key = CryptographyKey.from('8000000000000000000000000000000000000000000000000000000000000000', 'hex');
        let iv = Buffer.alloc(24, 0);
        let output = await sodium.crypto_stream(256, iv, key);
        let testVector = '93D88C085B8433B1FBAD2221FAD718078D96119F727D27F0547F9F3D29DE1358' +
                         'F3FE3D9EEACF59E894FA76E6507F567B4A0796DD00D8BFC736344A9906CB1F5D';
        expect(output.slice(0, 64).toString('hex').toUpperCase()).to.be.equals(testVector);
        testVector = '17FD2BD86D095016D8367E0DD47D3E4A18DAE7BB24F8B5E3E9F52C4A493BE982' +
                     'ECA8E89A4DEC78467E31087A1ACDA83754BEFB273AB27EB396EB4957F7166C25';
        expect(output.slice(192, 256).toString('hex').toUpperCase()).to.be.equals(testVector);

        key = CryptographyKey.from('80808080808080808080808080808080808080808080808080808080808080808080', 'hex');
        output = await sodium.crypto_stream_xor('Test message', iv, key);
        expect(output.toString('hex')).to.be.equals('1071d0355cb22c4c4e00303f');
    });

    it('SodiumPlus.randombytes_buf', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let a, b;
        for (let i = 0; i < 100; i++) {
            a = await sodium.randombytes_buf(64);
            b = await sodium.randombytes_buf(64);
            expect(a.toString('hex')).to.not.equals(b.toString('hex'));
        }
    });

    it('SodiumPlus.randombytes_uniform', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let a, b;
        for (let i = 0; i < 100; i++) {
            a = await sodium.randombytes_uniform(0x3fffffff);
            b = await sodium.randombytes_uniform(0x3fffffff);
            expect(a).to.not.equals(b);
        }
    });

    it('SodiumPlus.sodium_add', async () => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let foo = Buffer.from('ed000000', 'hex');
        let bar = Buffer.from('01000000', 'hex');
        let baz = await sodium.sodium_add(foo, bar);
        expect(baz.toString('hex')).to.be.equals('ee000000');

        bar = Buffer.from('ff000000', 'hex');
        baz = await sodium.sodium_add(baz, bar);
        expect(baz.toString('hex')).to.be.equals('ed010000');

        foo = Buffer.from('ffffffff', 'hex');
        bar = Buffer.from('01000000', 'hex');
        baz = await sodium.sodium_add(foo, bar);
        expect(baz.toString('hex')).to.be.equals('00000000');
        bar = Buffer.from('02000000', 'hex');
        baz = await sodium.sodium_add(foo, bar);
        expect(baz.toString('hex')).to.be.equals('01000000');
    });

    it('SodiumPlus.sodium_compare', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let a = Buffer.from('80808080', 'hex');
        let b = Buffer.from('81808080', 'hex');
        let c = Buffer.from('80808081', 'hex');

        expect(await sodium.sodium_compare(a, a)).to.be.equals(0);
        expect(await sodium.sodium_compare(b, b)).to.be.equals(0);
        expect(await sodium.sodium_compare(c, c)).to.be.equals(0);
        expect(await sodium.sodium_compare(a, b)).to.be.below(0);
        expect(await sodium.sodium_compare(b, a)).to.be.above(0);
        expect(await sodium.sodium_compare(a, c)).to.be.below(0);
        expect(await sodium.sodium_compare(c, a)).to.be.above(0);
        expect(await sodium.sodium_compare(b, c)).to.be.below(0);
        expect(await sodium.sodium_compare(c, b)).to.be.above(0);
    });

    it('SodiumPlus.sodium_increment', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let a = Buffer.from('80808080', 'hex');
        let b = Buffer.from('81808080', 'hex');
        await sodium.sodium_increment(a);
        expect(await sodium.sodium_compare(b, a)).to.be.equals(0);

        a = Buffer.from('ffffffff', 'hex');
        b = Buffer.from('00000000', 'hex');
        await sodium.sodium_increment(a);
        expect(await sodium.sodium_compare(b, a)).to.be.equals(0);
    });
    it('SodiumPlus.sodium_is_zero', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let buf;
        buf = Buffer.from('00', 'hex');
        expect(await sodium.sodium_is_zero(buf, 1)).to.be.equals(true);
        buf = Buffer.from('01', 'hex');
        expect(await sodium.sodium_is_zero(buf, 1)).to.be.equals(false);
    });

    it('SodiumPlus.sodium_memcmp', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let a, b, c;
        a = await sodium.randombytes_buf(32);
        b = await sodium.randombytes_buf(32);
        c = await Util.cloneBuffer(b);

        expect(await sodium.sodium_memcmp(a, b)).to.be.equals(false);
        expect(await sodium.sodium_memcmp(a, c)).to.be.equals(false);
        expect(await sodium.sodium_memcmp(b, c)).to.be.equals(true);
        expect(await sodium.sodium_memcmp(c, b)).to.be.equals(true);
    });

    it('SodiumPlus.sodium_memzero', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let buf = await sodium.randombytes_buf(16);
        expect(buf.toString('hex')).to.not.equals('00000000000000000000000000000000');
        await sodium.sodium_memzero(buf);
        expect(buf.toString('hex')).to.be.equals('00000000000000000000000000000000');
    });

    it('SodiumPlus.sodium_pad', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        let buf, size, padded, unpadded;
        for (let i = 0; i < 100; i++) {
            buf = await sodium.randombytes_buf(
                await sodium.randombytes_uniform(96) + 16
            );
            size = await sodium.randombytes_uniform(96) + 5;
            padded = await sodium.sodium_pad(buf, size);
            unpadded = await sodium.sodium_unpad(padded, size);
            expect(unpadded.toString('hex')).to.be.equals(buf.toString('hex'));
        }
    });
});
