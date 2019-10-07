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
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} keypair
     * @return {Promise<Buffer>}
     *
     */
    async crypto_box(plaintext, nonce, keypair) {
        return Util.toBuffer(
            await this.sodium.crypto_box_easy(
                await Util.toBuffer(plaintext),
                await Util.toBuffer(nonce),
                keypair.getBuffer().slice(32, 64),
                keypair.getBuffer().slice(0, 32)
            )
        );
    }

    /**
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {CryptographyKey} keypair
     * @return {Promise<Buffer>}
     */
    async crypto_box_open(ciphertext, nonce, keypair) {
        return Util.toBuffer(
            await this.sodium.crypto_box_open_easy(
                await Util.toBuffer(ciphertext),
                await Util.toBuffer(nonce),
                keypair.getBuffer().slice(0, 32),
                keypair.getBuffer().slice(32, 64)
            )
        );
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_box_keypair() {
        let obj = this.sodium.crypto_box_keypair();
        return new CryptographyKey(
            Buffer.concat([
                await Util.toBuffer(obj.privateKey),
                await Util.toBuffer(obj.publicKey)
            ])
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
