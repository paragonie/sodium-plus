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
     * @param {number} number
     * @return {Promise<Buffer>}
     */
    async randombytes_buf(number) {
        let buf = Buffer.alloc(number);
        this.sodium.randombytes_buf(buf);
        return buf;
    }
};
