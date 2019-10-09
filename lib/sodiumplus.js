const Backend = require('./backend');
const CryptographyKey = require('./cryptography-key');
const Ed25519SecretKey = require('./keytypes/ed25519sk');
const Ed25519PublicKey = require('./keytypes/ed25519pk');
const LibsodiumWrappersBackend = require('./backend/libsodium-wrappers');
const SodiumNativeBackend = require('./backend/sodiumnative');
const Util = require('./util');
const X25519PublicKey = require('./keytypes/x25519pk');
const X25519SecretKey = require('./keytypes/x25519sk');

const CRYPTO_PWHASH_ALG_DEFAULT = 2;

class SodiumPlus {
    constructor(backend) {
        if (!(backend instanceof Backend)) {
            throw new TypeError('Backend object must implement the backend function');
        }
        this.backend = backend;
        Util.populateConstants(this);
    }

    /**
     * @return {string}
     */
    getBackendName() {
        return this.backend.backendName;
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
        Util.populateConstants(backend);
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
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {X25519SecretKey} myPrivateKey
     * @param {X25519PublicKey} theirPublicKey
     * @return {Promise<Buffer>}
     */
    async crypto_box(plaintext, nonce, myPrivateKey, theirPublicKey) {
        if (!(myPrivateKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 3 must be an instance of CryptographyKey');
        }
        if (!(theirPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 4 must be an instance of CryptographyKey');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new Error('Nonce must be a buffer of exactly 24 bytes');
        }
        return this.backend.crypto_box(
            plaintext,
            nonce,
            myPrivateKey,
            theirPublicKey
        );
    }

    /**
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {X25519SecretKey} myPrivateKey
     * @param {X25519PublicKey} theirPublicKey
     * @return {Promise<Buffer>}
     */
    async crypto_box_open(ciphertext, nonce, myPrivateKey, theirPublicKey) {
        if (!(myPrivateKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 3 must be an instance of CryptographyKey');
        }
        if (!(theirPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 4 must be an instance of CryptographyKey');
        }
        if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 16) {
            console.log(ciphertext);
            throw new Error('Ciphertext must be a buffer of at least 16 bytes');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new Error('Nonce must be a buffer of exactly 24 bytes');
        }
        return this.backend.crypto_box_open(
            ciphertext,
            nonce,
            myPrivateKey,
            theirPublicKey
        );
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_box_keypair() {
        return this.backend.crypto_box_keypair();
    }

    /**
     *
     * @param {X25519SecretKey} sKey
     * @param {X25519PublicKey} pKey
     * @return {Promise<CryptographyKey>}
     */
    async crypto_box_keypair_from_secretkey_and_secretkey(sKey, pKey) {
        if (!(sKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        if (!(pKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        return await this.backend.crypto_box_keypair_from_secretkey_and_secretkey(sKey, pKey);
    }

    /**
     * @param {CryptographyKey} keypair
     * @return {Promise<X25519SecretKey>}
     */
    async crypto_box_secretkey(keypair) {
        if (keypair.getLength()!== 64) {
            throw new Error('Keypair must be 64 bytes');
        }
        return new X25519SecretKey(
            Buffer.from(keypair.getBuffer().slice(0, 32))
        );
    }

    /**
     * @param {CryptographyKey} keypair
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_box_publickey(keypair) {
        if (keypair.getLength() !== 64) {
            throw new Error('Keypair must be 64 bytes');
        }
        return new X25519PublicKey(
            Buffer.from(keypair.getBuffer().slice(32, 64))
        );
    }

    /**
     * @param {X25519SecretKey} secretKey
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_box_publickey_from_secretkey(secretKey) {
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        return new X25519PublicKey(
            await this.backend.crypto_scalarmult_base(secretKey)
        );
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {X25519PublicKey} publicKey
     * @return {Promise<Buffer>}
     */
    async crypto_box_seal(plaintext, publicKey) {
        if (!(publicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        return await this.backend.crypto_box_seal(plaintext, publicKey);
    }

    /**
     * @param {Buffer} ciphertext
     * @param {X25519PublicKey} publicKey
     * @param {X25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_box_seal_open(ciphertext, publicKey, secretKey) {
        if (!(publicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 3 must be an instance of X25519SecretKey');
        }
        return await this.backend.crypto_box_seal_open(ciphertext, publicKey, secretKey);
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey|null} key
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash(message, key = null, outputLength = 32) {
        return await this.backend.crypto_generichash(message, key, outputLength);
    }

    /**
     * @param {CryptographyKey|null} key
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash_init(key = null, outputLength = 32) {
        return await this.backend.crypto_generichash_init(key, outputLength);
    }


    /**
     * @param {*} state
     * @param {string|Buffer} message
     * @return {Promise<*>}
     */
    async crypto_generichash_update(state, message) {
        return await this.backend.crypto_generichash_update(state, message);
    }

    /**
     * @param {*} state
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash_final(state, outputLength = 32) {
        return await this.backend.crypto_generichash_final(state, outputLength);
    }
    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_generichash_keygen() {
        return new CryptographyKey(await this.backend.randombytes_buf(32));
    }

    /**
     * @param {number} length
     * @param {string|Buffer} password
     * @param {Buffer} salt
     * @param {number} opslimit
     * @param {number} memlimit
     * @param {number} algorithm
     * @return {Promise<Buffer>}
     */
    async crypto_pwhash(length, password, salt, opslimit, memlimit, algorithm = CRYPTO_PWHASH_ALG_DEFAULT) {
        return await this.backend.crypto_pwhash(length, password, salt, opslimit, memlimit, algorithm);
    }

    /**
     * @param {string|Buffer} password
     * @param {number} opslimit
     * @param {number} memlimit
     * @param {number} algorithm
     * @return {Promise<string>}
     */
    async crypto_pwhash_str(password, opslimit, memlimit) {
        return await this.backend.crypto_pwhash_str(password, opslimit, memlimit);
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} hash
     * @return {Promise<boolean>}
     */
    async crypto_pwhash_str_verify(password, hash) {
        return await this.backend.crypto_pwhash_str_verify(password, hash);
    }

    /**
     * @param {string|Buffer} hash
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<boolean>}
     */
    async crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit) {
        return await this.backend.crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit);
    }

    /**
     * @param {X25519SecretKey} secretKey
     * @param {X25519PublicKey} publicKey
     * @return {Promise<CryptographyKey>}
     */
    async crypto_scalarmult(secretKey, publicKey) {
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        if (!(publicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        return await this.backend.crypto_scalarmult(secretKey, publicKey);
    }

    /**
     * @param {X25519SecretKey} secretKey
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_scalarmult_base(secretKey) {
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        return new X25519PublicKey(
            await this.backend.crypto_scalarmult_base(secretKey)
        );
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_secretbox(plaintext, nonce, key) {
        if (key.isEd25519Key() || key.isEd25519Key()) {
            throw new TypeError('Argument 3 must not be an asymmetric key');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new Error('Nonce must be a buffer of exactly 24 bytes');
        }

        return await this.backend.crypto_secretbox(
            plaintext,
            nonce,
            key
        );
    }

    /**
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_secretbox_open(ciphertext, nonce, key) {
        if (key.isEd25519Key() || key.isEd25519Key()) {
            throw new TypeError('Argument 3 must not be an asymmetric key');
        }
        if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 16) {
            throw new Error('Ciphertext must be a buffer of at least 16 bytes');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new Error('Nonce must be a buffer of exactly 24 bytes');
        }
        return await this.backend.crypto_secretbox_open(
            ciphertext,
            nonce,
            key
        );
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_secretbox_keygen() {
        return new CryptographyKey(await this.backend.randombytes_buf(32));
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_shorthash(message, key) {
        return await this.backend.crypto_shorthash(message, key);
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_shorthash_keygen() {
        return new CryptographyKey(await this.backend.randombytes_buf(16));
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign(message, secretKey) {
        if (!(secretKey instanceof Ed25519SecretKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519SecretKey');
        }
        return this.backend.crypto_sign(message, secretKey);
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519PublicKey} publicKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign_open(message, publicKey) {
        if (!(publicKey instanceof Ed25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519PublicKey');
        }
        return this.backend.crypto_sign_open(message, publicKey);
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign_detached(message, secretKey) {
        if (!(secretKey instanceof Ed25519SecretKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519SecretKey');
        }
        return this.backend.crypto_sign_detached(message, secretKey);
    }

    /**
     * @param {string|Buffer} message,
     * @param {Ed25519PublicKey} publicKey
     * @param {Buffer} signature
     * @return {Promise<boolean>}
     */
    async crypto_sign_verify_detached(message, publicKey, signature) {
        if (!(publicKey instanceof Ed25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519PublicKey');
        }
        return this.backend.crypto_sign_verify_detached(message, publicKey, signature);
    }

    /**
     * @param {CryptographyKey} keypair
     * @return {Promise<Ed25519SecretKey>}
     */
    async crypto_sign_secretkey(keypair) {
        if (keypair.getLength() !== 96) {
            throw new Error('Keypair must be 96 bytes');
        }
        return new Ed25519SecretKey(
            await Util.toBuffer(
                keypair.getBuffer().slice(0, 64)
            )
        );
    }

    /**
     * @param {CryptographyKey} keypair
     * @return {Promise<Ed25519PublicKey>}
     */
    async crypto_sign_publickey(keypair) {
        if (keypair.getLength() !== 96) {
            throw new Error('Keypair must be 96 bytes');
        }
        return new Ed25519PublicKey(
            keypair.getBuffer().slice(64, 96)
        );
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_sign_keypair() {
        return this.backend.crypto_sign_keypair();
    }

    /**
     * @param {Buffer} buf
     * @return {Promise<void>}
     */
    async sodium_memzero(buf) {
        await this.backend.sodium_memzero(buf);
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
