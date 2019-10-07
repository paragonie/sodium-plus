let loaded = false;
let _sodium;
try {
    _sodium = require('sodium-native');
    loaded = true;
} catch (e) {
    _sodium = {};
}
const Backend = require('../backend');
const CryptographyKey = require('../cryptography-key');
const Util = require('../util');
const toBuffer = require('typedarray-to-buffer');

module.exports = class SodiumNativeBackend extends Backend {
    constructor(lib) {
        super(lib);
        this.sodium = lib;
    }

    static async init() {
        if (!loaded) {
            throw new Error('sodium-native not installed');
        }
        return new SodiumNativeBackend(_sodium);
    }

    /**
     * @param {Uint8Array} val
     * @param {Uint8Array} addv
     * @return {Promise<Buffer>}
     */
    async add(val, addv) {
        let buf = await Util.cloneBuffer(val);
        this.sodium.sodium_add(buf, addv);
        return buf;
    }


    /**
     *
     * @param {String|Buffer} ciphertext
     * @param {String|Buffer} assocData
     * @param {String|Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, assocData, nonce, key) {
        let plaintext = Buffer.alloc(ciphertext.length - 16, 0);
        this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext,
            null,
            await Util.toBuffer(ciphertext),
            await Util.toBuffer(assocData),
            await Util.toBuffer(nonce),
            key.getBuffer()
        );
        return plaintext;
    }

    /**
     *
     * @param {String|Buffer} plaintext
     * @param {String|Buffer} assocData
     * @param {String|Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, assocData, nonce, key) {
        let ciphertext = Buffer.alloc(plaintext.length + 16, 0);
        let kbuf = key.getBuffer();
        this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            await Util.toBuffer(plaintext),
            await Util.toBuffer(assocData),
            null,
            await Util.toBuffer(nonce),
            kbuf
        );
        return ciphertext;
    }

    /**
     * @param {String|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<buffer>}
     */
    async crypto_auth(message, key) {
        let output = Buffer.alloc(32);
        this.sodium.crypto_auth(
            output,
            await Util.toBuffer(message),
            key.getBuffer()
        );
        return toBuffer(output);
    }

    /**
     * @param {Buffer} mac
     * @param {String|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<boolean>}
     */
    async crypto_auth_verify(mac, message, key) {
        return this.sodium.crypto_auth_verify(
            mac,
            await Util.toBuffer(message),
            key.getBuffer()
        );
    }
    /**
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} keypair
     * @return {Promise<Buffer>}
     *
     */
    async crypto_box(plaintext, nonce, keypair) {
        let ciphertext = Buffer.alloc(plaintext.length + 16);
        this.sodium.crypto_box_easy(
            ciphertext,
            plaintext,
            nonce,
            keypair.getBuffer().slice(32, 64),
            keypair.getBuffer().slice(0, 32)
        );
        return Util.toBuffer(ciphertext);
    }

    /**
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {CryptographyKey} keypair
     * @return {Promise<Buffer>}
     */
    async crypto_box_open(ciphertext, nonce, keypair) {
        let plaintext = Buffer.alloc(ciphertext.length + 16);
        this.sodium.crypto_box_open_easy(
            plaintext,
            ciphertext,
            nonce,
            keypair.getBuffer().slice(32, 64),
            keypair.getBuffer().slice(0, 32)
        );
        return Util.toBuffer(plaintext);
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_box_keypair() {
        let sK = Buffer.alloc(32, 0);
        let pK = Buffer.alloc(32, 0);
        this.sodium.crypto_box_keypair(sK, pK);
        return new CryptographyKey(
            Buffer.concat([sK, pK])
        );
    }

    /**
     * @param {number} number
     * @return {Promise<Buffer>}
     */
    async randombytes_buf(number) {
        let buf = Buffer.alloc(number);
        this.sodium.randombytes_buf(buf);
        return buf;
    }
};
