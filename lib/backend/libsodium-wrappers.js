const _sodium = require('libsodium-wrappers');
const Backend = require('../backend');
const CryptographyKey = require('../cryptography-key');
const Util = require('../util');
const toBuffer = require('typedarray-to-buffer');

module.exports = class LibsodiumWrappersBackend extends Backend {
    constructor(lib) {
        super(lib);
        this.sodium = lib;
    }

    static async init() {
        await _sodium.ready;
        return new LibsodiumWrappersBackend(_sodium);
    }

    /**
     * @param {Uint8Array} val
     * @param {Uint8Array} addv
     * @return {Promise<Buffer>}
     */
    async add(val, addv) {
        let buf = await Util.cloneBuffer(val);
        this.sodium.add(buf, addv);
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
        return toBuffer(
            this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                ciphertext,
                assocData,
                nonce,
                key.getBuffer()
            )
        );
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
        return toBuffer(
            this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                assocData,
                null,
                nonce,
                key.getBuffer()
            )
        );
    }

    /**
     * @param {String|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<buffer>}
     */
    async crypto_auth(message, key) {
        return toBuffer(
            this.sodium.crypto_auth(
                message,
                key.getBuffer()
            )
        );
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
            message,
            key.getBuffer()
        );
    }

    /**
     * @param {number} number
     * @return {Promise<Buffer>}
     */
    async randombytes_buf(number) {
        return Util.toBuffer(await this.sodium.randombytes_buf(number));
    }
};
