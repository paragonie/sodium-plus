const Backend = require('./backend');
const CryptographyKey = require('./cryptography-key');
const LibsodiumWrappersBackend = require('./backend/libsodium-wrappers');
const SodiumNativeBackend = require('./backend/sodiumnative');
const Util = require('./util');

class SodiumPlus {
    constructor(backend) {
        if (!(backend instanceof Backend)) {
            throw new TypeError('Backend object must implement the backend function');
        }
        this.backend = backend;
    }

    /**
     * @return {boolean}
     */
    isSodiumNative() {
        return (this.backend instanceof SodiumNativeBackend);
    }

    /**
     * @return {boolean}
     */
    isLibsodiumWrappers() {
        return (this.backend instanceof LibsodiumWrappersBackend);
    }

    /**
     * Automatically select a backend.
     *
     * @return {Promise<SodiumPlus>}
     */
    static async auto() {
        let backend;
        try {
            backend = await SodiumNativeBackend.init();
        } catch (e) {
            backend = await LibsodiumWrappersBackend.init();
        }
        if (!backend) {
            backend = await LibsodiumWrappersBackend.init();
        }
        return new SodiumPlus(backend);
    }

    /**
     * @return {Promise<void>}
     */
    async ensureLoaded() {
        if (typeof (this.backend) === 'undefined') {
            try {
                await SodiumPlus.auto();
            } catch (e) {
                this.backend = await LibsodiumWrappersBackend.init();
            }
        }
    }

    /**
     * @param {Buffer} val
     * @param {Buffer} addv
     * @return {Promise<Buffer>}
     */
    async add(val, addv) {
        await this.ensureLoaded();
        return await this.backend.add(
            await Util.toBuffer(val),
            await Util.toBuffer(addv)
        );
    }

    /**
     *
     * @param {String|Buffer} ciphertext
     * @param {String|Buffer} nonce
     * @param {CryptographyKey} key
     * @param {String|Buffer} assocData
     * @return {Promise<Buffer>}
     */
    async crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, nonce, key, assocData = '') {
        await this.ensureLoaded();
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 4 must be an instance of CryptographyKey');
        }
        return await this.backend.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext,
            assocData,
            nonce,
            key
        );
    }
    /**
     *
     * @param {String|Buffer} plaintext
     * @param {String|Buffer} nonce
     * @param {CryptographyKey} key
     * @param {String|Buffer} assocData
     * @return {Promise<Buffer>}
     */
    async crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, nonce, key, assocData = '') {
        await this.ensureLoaded();
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 4 must be an instance of CryptographyKey');
        }

        return await this.backend.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            assocData.length > 0 ? assocData : null,
            nonce,
            key
        );
    }

    /**
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_aead_xchacha20poly1305_ietf_keygen() {
        return new CryptographyKey(await this.backend.randombytes_buf(32));
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_auth(message, key) {
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 2 must be an instance of CryptographyKey');
        }
        await this.ensureLoaded();
        return await this.backend.crypto_auth(message, key);
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_auth_keygen() {
        return new CryptographyKey(await this.backend.randombytes_buf(32));
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @param {Buffer} mac
     * @return {Promise<boolean>}
     */
    async crypto_auth_verify(message, key, mac) {
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 2 must be an instance of CryptographyKey');
        }
        await this.ensureLoaded();
        return await this.backend.crypto_auth_verify(mac, message, key);
    }

    /**
     *
     * @param {number} num
     * @return {Promise<Buffer>}
     */
    async randombytes_buf(num) {
        await this.ensureLoaded();
        return await this.backend.randombytes_buf(num);
    }
}

module.exports = SodiumPlus;
