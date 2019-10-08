const _sodium = require('libsodium-wrappers');
const Backend = require('../backend');
const CryptographyKey = require('../cryptography-key');
const Util = require('../util');
const toBuffer = require('typedarray-to-buffer');

module.exports = class LibsodiumWrappersBackend extends Backend {
    constructor(lib) {
        super(lib);
        this.sodium = lib;
        this.backendName = 'LibsodiumWrappersBackend';
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
     * @param {CryptographyKey} sk
     * @param {CryptographyKey} pk
     * @return {Promise<Buffer>}
     *
     */
    async crypto_box(plaintext, nonce, sk, pk) {
        return Util.toBuffer(
            await this.sodium.crypto_box_easy(
                await Util.toBuffer(plaintext),
                await Util.toBuffer(nonce),
                pk.getBuffer(),
                sk.getBuffer()
            )
        );
    }

    /**
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {CryptographyKey} sk
     * @param {CryptographyKey} pk
     * @return {Promise<Buffer>}
     */
    async crypto_box_open(ciphertext, nonce, sk, pk) {
        return Util.toBuffer(
            await this.sodium.crypto_box_open_easy(
                await Util.toBuffer(ciphertext),
                await Util.toBuffer(nonce),
                pk.getBuffer(),
                sk.getBuffer()
            )
        );
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {CryptographyKey} pk
     * @return {Promise<Buffer>}
     *
     */
    async crypto_box_seal(plaintext, pk) {
        return Util.toBuffer(
            await this.sodium.crypto_box_seal(
                await Util.toBuffer(plaintext),
                pk.getBuffer()
            )
        );
    }

    /**
     * @param {Buffer} ciphertext
     * @param {CryptographyKey} pk
     * @param {CryptographyKey} sk
     * @return {Promise<Buffer>}
     */
    async crypto_box_seal_open(ciphertext, pk, sk) {
        return Util.toBuffer(
            await this.sodium.crypto_box_seal_open(
                await Util.toBuffer(ciphertext),
                pk.getBuffer(),
                sk.getBuffer()
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
     * @param {string|Buffer} message
     * @param {CryptographyKey|null} key
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash(message, key = null, outputLength = 32) {
        if (key) {
            return await Util.toBuffer(
                this.sodium.crypto_generichash(
                    outputLength,
                    await Util.toBuffer(message),
                    key.getBuffer()
                )
            );
        }
        return await Util.toBuffer(
            this.sodium.crypto_generichash(
                outputLength,
                await Util.toBuffer(message)
            )
        );
    }

    /**
     * @param {CryptographyKey|null} key
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash_init(key = null, outputLength = 32) {
        if (key) {
            return this.sodium.crypto_generichash_init(key.getBuffer(), outputLength);
        }
        return this.sodium.crypto_generichash_init(null, outputLength);
    }

    /**
     * @param {*} state
     * @param {string|Buffer} message
     * @return {Promise<*>}
     */
    async crypto_generichash_update(state, message) {
        return this.sodium.crypto_generichash_update(state, await Util.toBuffer(message));
    }

    /**
     * @param {*} state
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash_final(state, outputLength = 32) {
        return await Util.toBuffer(
            this.sodium.crypto_generichash_final(state, outputLength)
        );
    }

    /**
     * @param {X25519SecretKey} secretKey
     * @param {X25519PublicKey} publicKey
     * @return {Promise<CryptographyKey>}
     */
    async crypto_scalarmult(secretKey, publicKey) {
        return new CryptographyKey(
            await Util.toBuffer(
                this.sodium.crypto_scalarmult(secretKey.getBuffer(), publicKey.getBuffer())
            )
        );
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_secretbox(plaintext, nonce, key) {
        return await Util.toBuffer(
            this.sodium.crypto_secretbox_easy(
                await Util.toBuffer(plaintext),
                nonce,
                key.getBuffer()
            )
        );
    }

    /**
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_secretbox_open(ciphertext, nonce, key) {
        return await Util.toBuffer(
            this.sodium.crypto_secretbox_open_easy(
                await Util.toBuffer(ciphertext),
                nonce,
                key.getBuffer()
            )
        );
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign(message, secretKey) {
        return await Util.toBuffer(
            this.sodium.crypto_sign(
                await Util.toBuffer(message),
                secretKey.getBuffer()
            )
        );
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519PublicKey} publicKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign_open(message, publicKey) {
        return await Util.toBuffer(
            this.sodium.crypto_sign_open(
                message,
                publicKey.getBuffer()
            )
        );
    }
    /**
     * @param {string|Buffer} message,
     * @param {Ed25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign_detached(message, secretKey) {
        return await Util.toBuffer(
            this.sodium.crypto_sign_detached(
                await Util.toBuffer(message),
                secretKey.getBuffer()
            )
        );
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519PublicKey} publicKey
     * @param {Buffer} signature
     * @return {Promise<Buffer>}
     */
    async crypto_sign_verify_detached(message, publicKey, signature) {
        return this.sodium.crypto_sign_verify_detached(
            signature,
            await Util.toBuffer(message),
            publicKey.getBuffer()
        );
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_sign_keypair() {
        let obj = this.sodium.crypto_sign_keypair();
        return new CryptographyKey(
            Buffer.concat([
                await Util.toBuffer(obj.privateKey),
                await Util.toBuffer(obj.publicKey)
            ])
        );
    }

    /**
     *
     * @param {CryptographyKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_scalarmult_base(secretKey) {
        return Util.toBuffer(
            this.sodium.crypto_scalarmult_base(secretKey.getBuffer())
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
