const Backend = require('./backend');
const CryptographyKey = require('./cryptography-key');
const Ed25519SecretKey = require('./keytypes/ed25519sk');
const Ed25519PublicKey = require('./keytypes/ed25519pk');
const LibsodiumWrappersBackend = require('./backend/libsodium-wrappers');
const SodiumError = require('./sodium-error');
const SodiumNativeBackend = require('./backend/sodiumnative');
const X25519PublicKey = require('./keytypes/x25519pk');
const X25519SecretKey = require('./keytypes/x25519sk')
const Util = require('./util');

class SodiumPlus {
    constructor(backend) {
        if (!(backend instanceof Backend)) {
            throw new TypeError('Backend object must implement the backend function');
        }
        this.backend = backend;
        Util.populateConstants(this);
    }

    /**
     * Returns the name of the current active backend.
     * This method is NOT async.
     *
     * @return {string}
     */
    getBackendName() {
        return this.backend.backendName;
    }

    /**
     * Is this powered by sodium-native?
     * This method is NOT async.
     *
     * @return {boolean}
     */
    isSodiumNative() {
        return (this.backend instanceof SodiumNativeBackend);
    }

    /**
     * Is this powered by libsodium-wrappers?
     * This method is NOT async.
     *
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
     * If our backend isn't defined, it will trigger an autoload.
     *
     * Mostly used internally. `await SodiumPlus.auto()` provides the same
     * exact guarantee as this method.
     *
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
     * Decrypt a message (and optional associated data) with XChaCha20-Poly1305
     *
     * @param {String|Buffer} ciphertext
     * @param {String|Buffer} nonce
     * @param {CryptographyKey} key
     * @param {String|Buffer} assocData
     * @return {Promise<Buffer>}
     * @throws {SodiumError}
     */
    async crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, nonce, key, assocData = '') {
        await this.ensureLoaded();
        if (nonce.length !== 24) {
            throw new SodiumError('Argument 2 must be 24 bytes');
        }
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 3 must be an instance of CryptographyKey');
        }
        return await this.backend.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext,
            assocData,
            nonce,
            key
        );
    }

    /**
     * Encrypt a message (and optional associated data) with XChaCha20-Poly1305.
     *
     * Throws a SodiumError if an invalid ciphertext/AAD is provided for this
     * nonce and key.
     *
     * @param {String|Buffer} plaintext
     * @param {String|Buffer} nonce
     * @param {CryptographyKey} key
     * @param {String|Buffer} assocData
     * @return {Promise<Buffer>}
     * @throws {SodiumError}
     */
    async crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, nonce, key, assocData = '') {
        await this.ensureLoaded();
        if (nonce.length !== 24) {
            throw new SodiumError('Argument 2 must be 24 bytes');
        }
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 3 must be an instance of CryptographyKey');
        }

        return await this.backend.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            assocData.length > 0 ? assocData : null,
            nonce,
            key
        );
    }

    /**
     * Generate an XChaCha20-Poly1305 key.
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_aead_xchacha20poly1305_ietf_keygen() {
        return new CryptographyKey(await this.backend.randombytes_buf(32));
    }

    /**
     * Get an authenticator for a message for a given key.
     *
     * Algorithm: HMAC-SHA512 truncated to 32 bytes.
     *
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_auth(message, key) {
        await this.ensureLoaded();
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
     * Verify an authenticator for a message for a given key.
     *
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @param {Buffer} mac
     * @return {Promise<boolean>}
     */
    async crypto_auth_verify(message, key, mac) {
        await this.ensureLoaded();
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 2 must be an instance of CryptographyKey');
        }
        await this.ensureLoaded();
        return await this.backend.crypto_auth_verify(mac, message, key);
    }

    /**
     * Public-key authenticated encryption.
     *
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {X25519SecretKey} myPrivateKey
     * @param {X25519PublicKey} theirPublicKey
     * @return {Promise<Buffer>}
     */
    async crypto_box(plaintext, nonce, myPrivateKey, theirPublicKey) {
        await this.ensureLoaded();
        if (!(myPrivateKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 3 must be an instance of CryptographyKey');
        }
        if (!(theirPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 4 must be an instance of CryptographyKey');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new SodiumError('Nonce must be a buffer of exactly 24 bytes');
        }
        return this.backend.crypto_box(
            plaintext,
            nonce,
            myPrivateKey,
            theirPublicKey
        );
    }

    /**
     * Public-key authenticated decryption.
     *
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {X25519SecretKey} myPrivateKey
     * @param {X25519PublicKey} theirPublicKey
     * @return {Promise<Buffer>}
     */
    async crypto_box_open(ciphertext, nonce, myPrivateKey, theirPublicKey) {
        await this.ensureLoaded();
        if (!(myPrivateKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 3 must be an instance of CryptographyKey');
        }
        if (!(theirPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 4 must be an instance of CryptographyKey');
        }
        if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 16) {
            throw new SodiumError('Ciphertext must be a buffer of at least 16 bytes');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new SodiumError('Nonce must be a buffer of exactly 24 bytes');
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
        await this.ensureLoaded();
        return this.backend.crypto_box_keypair();
    }

    /**
     * Combine two X25519 keys (secret, public) into a keypair object.
     *
     * @param {X25519SecretKey} sKey
     * @param {X25519PublicKey} pKey
     * @return {Promise<CryptographyKey>}
     */
    async crypto_box_keypair_from_secretkey_and_secretkey(sKey, pKey) {
        await this.ensureLoaded();
        if (!(sKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        if (!(pKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        return await this.backend.crypto_box_keypair_from_secretkey_and_secretkey(sKey, pKey);
    }

    /**
     * Extract the secret key from an X25519 keypair object.
     *
     * @param {CryptographyKey} keypair
     * @return {Promise<X25519SecretKey>}
     */
    async crypto_box_secretkey(keypair) {
        if (keypair.getLength()!== 64) {
            throw new SodiumError('Keypair must be 64 bytes');
        }
        return new X25519SecretKey(
            Buffer.from(keypair.getBuffer().slice(0, 32))
        );
    }

    /**
     * Extract the public key from an X25519 keypair object.
     *
     * @param {CryptographyKey} keypair
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_box_publickey(keypair) {
        if (keypair.getLength() !== 64) {
            throw new SodiumError('Keypair must be 64 bytes');
        }
        return new X25519PublicKey(
            Buffer.from(keypair.getBuffer().slice(32, 64))
        );
    }

    /**
     * Derive the public key from a given X25519 secret key.
     *
     * @param {X25519SecretKey} secretKey
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_box_publickey_from_secretkey(secretKey) {
        await this.ensureLoaded();
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        return new X25519PublicKey(
            await this.backend.crypto_scalarmult_base(secretKey)
        );
    }

    /**
     * Anonymous public-key encryption. (Message integrity is still assured.)
     *
     * @param {string|Buffer} plaintext
     * @param {X25519PublicKey} publicKey
     * @return {Promise<Buffer>}
     */
    async crypto_box_seal(plaintext, publicKey) {
        await this.ensureLoaded();
        if (!(publicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        return await this.backend.crypto_box_seal(plaintext, publicKey);
    }

    /**
     * Anonymous public-key decryption. (Message integrity is still assured.)
     *
     * @param {Buffer} ciphertext
     * @param {X25519PublicKey} publicKey
     * @param {X25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_box_seal_open(ciphertext, publicKey, secretKey) {
        await this.ensureLoaded();
        if (!(publicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 3 must be an instance of X25519SecretKey');
        }
        return await this.backend.crypto_box_seal_open(ciphertext, publicKey, secretKey);
    }

    /**
     * Generic-purpose cryptographic hash.
     *
     * @param {string|Buffer} message
     * @param {CryptographyKey|null} key
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash(message, key = null, outputLength = 32) {
        await this.ensureLoaded();
        return await this.backend.crypto_generichash(message, key, outputLength);
    }

    /**
     * Initialize a BLAKE2 hash context for stream hashing.
     *
     * @param {CryptographyKey|null} key
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash_init(key = null, outputLength = 32) {
        await this.ensureLoaded();
        return await this.backend.crypto_generichash_init(key, outputLength);
    }


    /**
     * Update the BLAKE2 hash state with a block of data.
     *
     * @param {*} state
     * @param {string|Buffer} message
     * @return {Promise<*>}
     */
    async crypto_generichash_update(state, message) {
        await this.ensureLoaded();
        return await this.backend.crypto_generichash_update(state, message);
    }

    /**
     * Obtain the final BLAKE2 hash output.
     *
     * @param {*} state
     * @param {number} outputLength
     * @return {Promise<Buffer>}
     */
    async crypto_generichash_final(state, outputLength = 32) {
        await this.ensureLoaded();
        return await this.backend.crypto_generichash_final(state, outputLength);
    }

    /**
     * Generate a 256-bit random key for BLAKE2.
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_generichash_keygen() {
        return new CryptographyKey(
            await this.backend.randombytes_buf(this.CRYPTO_GENERICHASH_KEYBYTES)
        );
    }

    /**
     * Derive a subkey from a master key.
     *
     * @param {number} length
     * @param {number} subKeyId
     * @param {string|Buffer} context
     * @param {CryptographyKey} key
     * @return {Promise<CryptographyKey>}
     */
    async crypto_kdf_derive_from_key(length, subKeyId, context, key) {
        await this.ensureLoaded();
        if (length < 1) {
            throw new SodiumError('Length must be a positive integer.');
        }
        if (subKeyId < 0) {
            throw new SodiumError('Key ID must be an unsigned integer');
        }
        return await this.backend.crypto_kdf_derive_from_key(
            length,
            subKeyId,
            context,
            key
        );
    }

    /**
     * Generate a 256-bit random key for our KDF.
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_kdf_keygen() {
        return new CryptographyKey(
            await this.backend.randombytes_buf(this.CRYPTO_KDF_KEYBYTES)
        );
    }

    /**
     * This is functionally identical to crypto_box_keypair().
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_kx_keypair() {
        return this.crypto_box_keypair();
    }

    /**
     * Generate an X25519 keypair from a seed.
     *
     * @param {string|Buffer} seed
     * @return {Promise<CryptographyKey>}
     */
    async crypto_kx_seed_keypair(seed) {
        await this.ensureLoaded();
        let sk = await this.backend.crypto_generichash(seed, null, this.CRYPTO_KX_SECRETKEYBYTES);
        let pk = await this.backend.crypto_scalarmult_base(new CryptographyKey(sk));
        return new CryptographyKey(Buffer.concat([sk, pk]));
    }

    /**
     * Perform a key exchange from the client's perspective.
     *
     * Returns an array of two CryptographyKey objects.
     *
     * The first is meant for data sent from the server to the client (incoming decryption).
     * The second is meant for data sent from the client to the server (outgoing encryption).
     *
     * @param {X25519PublicKey} clientPublicKey
     * @param {X25519SecretKey} clientSecretKey
     * @param {X25519PublicKey} serverPublicKey
     * @return {Promise<CryptographyKey[]>}
     */
    async crypto_kx_client_session_keys(clientPublicKey, clientSecretKey, serverPublicKey) {
        await this.ensureLoaded();
        if (!(clientPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519PublicKey');
        }
        if (!(clientSecretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519SecretKey');
        }
        if (!(serverPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 3 must be an instance of X25519PublicKey');
        }
        return this.backend.crypto_kx_client_session_keys(clientPublicKey, clientSecretKey, serverPublicKey);
    }

    /**
     * Perform a key exchange from the server's perspective.
     *
     * Returns an array of two CryptographyKey objects.
     *
     * The first is meant for data sent from the client to the server (incoming decryption).
     * The second is meant for data sent from the server to the client (outgoing encryption).
     *
     * @param {X25519PublicKey} serverPublicKey
     * @param {X25519SecretKey} serverSecretKey
     * @param {X25519PublicKey} clientPublicKey
     * @return {Promise<CryptographyKey[]>}
     */
    async crypto_kx_server_session_keys(serverPublicKey, serverSecretKey, clientPublicKey) {
        await this.ensureLoaded();
        if (!(serverPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519PublicKey');
        }
        if (!(serverSecretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519SecretKey');
        }
        if (!(clientPublicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 3 must be an instance of X25519PublicKey');
        }
        return this.backend.crypto_kx_server_session_keys(serverPublicKey, serverSecretKey, clientPublicKey);
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_onetimeauth(message, key) {
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 2 must be an instance of CryptographyKey');
        }
        return await this.backend.crypto_onetimeauth(message, key);
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @param {Buffer} tag
     * @return {Promise<boolean>}
     */
    async crypto_onetimeauth_verify(message, key, tag) {
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Argument 2 must be an instance of CryptographyKey');
        }
        return await this.backend.crypto_onetimeauth_verify(message, key, tag);
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_onetimeauth_keygen() {
        return new CryptographyKey(
            await this.backend.randombytes_buf(32)
        );
    }

    /**
     * Derive a cryptography key from a password and salt.
     *
     * @param {number} length
     * @param {string|Buffer} password
     * @param {Buffer} salt
     * @param {number} opslimit
     * @param {number} memlimit
     * @param {number|null} algorithm
     * @return {Promise<CryptographyKey>}
     */
    async crypto_pwhash(length, password, salt, opslimit, memlimit, algorithm = null) {
        await this.ensureLoaded();
        if (!algorithm) {
            algorithm = this.CRYPTO_PWHASH_ALG_DEFAULT;
        }
        return new CryptographyKey(
            await this.backend.crypto_pwhash(length, password, salt, opslimit, memlimit, algorithm)
        );
    }

    /**
     * Get a password hash (in a safe-for-storage format)
     *
     * @param {string|Buffer} password
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<string>}
     */
    async crypto_pwhash_str(password, opslimit, memlimit) {
        await this.ensureLoaded();
        return await this.backend.crypto_pwhash_str(password, opslimit, memlimit);
    }

    /**
     * Verify a password against a known password hash
     *
     * @param {string|Buffer} password
     * @param {string|Buffer} hash
     * @return {Promise<boolean>}
     */
    async crypto_pwhash_str_verify(password, hash) {
        await this.ensureLoaded();
        return await this.backend.crypto_pwhash_str_verify(password, hash);
    }

    /**
     * Does this password need to be rehashed?
     *
     * @param {string|Buffer} hash
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<boolean>}
     */
    async crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit) {
        await this.ensureLoaded();
        return await this.backend.crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit);
    }

    /**
     * Elliptic Curve Diffie-Hellman key exchange
     *
     * @param {X25519SecretKey} secretKey
     * @param {X25519PublicKey} publicKey
     * @return {Promise<CryptographyKey>}
     */
    async crypto_scalarmult(secretKey, publicKey) {
        await this.ensureLoaded();
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        if (!(publicKey instanceof X25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of X25519PublicKey');
        }
        return await this.backend.crypto_scalarmult(secretKey, publicKey);
    }

    /**
     * Generate an X25519PublicKey from an X25519SecretKey
     *
     * @param {X25519SecretKey} secretKey
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_scalarmult_base(secretKey) {
        await this.ensureLoaded();
        if (!(secretKey instanceof X25519SecretKey)) {
            throw new TypeError('Argument 1 must be an instance of X25519SecretKey');
        }
        return new X25519PublicKey(
            await this.backend.crypto_scalarmult_base(secretKey)
        );
    }

    /**
     * Shared-key authenticated encryption
     *
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_secretbox(plaintext, nonce, key) {
        await this.ensureLoaded();
        if (key.isEd25519Key() || key.isEd25519Key()) {
            throw new TypeError('Argument 3 must not be an asymmetric key');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new SodiumError('Nonce must be a buffer of exactly 24 bytes');
        }

        return await this.backend.crypto_secretbox(
            plaintext,
            nonce,
            key
        );
    }

    /**
     * Shared-key authenticated decryption
     *
     * @param {Buffer} ciphertext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_secretbox_open(ciphertext, nonce, key) {
        await this.ensureLoaded();
        if (key.isEd25519Key() || key.isEd25519Key()) {
            throw new TypeError('Argument 3 must not be an asymmetric key');
        }
        if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 16) {
            throw new SodiumError('Ciphertext must be a buffer of at least 16 bytes');
        }
        if (!Buffer.isBuffer(nonce) || nonce.length !== 24) {
            throw new SodiumError('Nonce must be a buffer of exactly 24 bytes');
        }
        return await this.backend.crypto_secretbox_open(
            ciphertext,
            nonce,
            key
        );
    }

    /**
     * Generate a key for shared-key authenticated encryption.
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_secretbox_keygen() {
        return new CryptographyKey(
            await this.backend.randombytes_buf(this.CRYPTO_SECRETBOX_KEYBYTES)
        );
    }

    /**
     * @param {CryptographyKey} key
     * @return {Promise<array>}
     */
    async crypto_secretstream_xchacha20poly1305_init_push(key) {
        await this.ensureLoaded();
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Key must be an instance of CryptographyKey');
        }
        if (key.getLength() !== 32) {
            throw new SodiumError('crypto_secretstream keys must be 32 bytes long');
        }
        return this.backend.crypto_secretstream_xchacha20poly1305_init_push(key);
    }

    /**
     * @param {Buffer} header
     * @param {CryptographyKey} key
     * @return {Promise<array>}
     */
    async crypto_secretstream_xchacha20poly1305_init_pull(key, header) {
        await this.ensureLoaded();
        if (!Buffer.isBuffer(header)) {
            throw new TypeError('Header must be a buffer');
        }
        if (header.length !== 24) {
            throw new SodiumError('crypto_secretstream headers must be 24 bytes long');
        }
        if (!(key instanceof CryptographyKey)) {
            throw new TypeError('Key must be an instance of CryptographyKey');
        }
        if (key.getLength() !== 32) {
            throw new SodiumError('crypto_secretstream keys must be 32 bytes long');
        }
        return this.backend.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
    }

    /**
     * @param {*} state
     * @param {string|Buffer} message
     * @param {string|Buffer} ad
     * @param {number} tag
     * @return {Promise<Buffer>}
     */
    async crypto_secretstream_xchacha20poly1305_push(state, message, ad = '', tag = 0) {
        await this.ensureLoaded();
        return this.backend.crypto_secretstream_xchacha20poly1305_push(state, message, ad, tag);
    }

    /**
     * @param {*} state
     * @param {Buffer} ciphertext
     * @param {string|Buffer} ad
     * @param {number} tag
     * @return {Promise<Buffer>}
     */
    async crypto_secretstream_xchacha20poly1305_pull(state, ciphertext, ad = '', tag = 0) {
        await this.ensureLoaded();
        return this.backend.crypto_secretstream_xchacha20poly1305_pull(state, ciphertext, ad, tag);
    }

    /**
     * @param {*} state
     * @return {Promise<void>}
     */
    async crypto_secretstream_xchacha20poly1305_rekey(state) {
        await this.ensureLoaded();
        await this.backend.crypto_secretstream_xchacha20poly1305_rekey(state);
    }

    /**
     * Generate a key for shared-key authenticated encryption.
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_secretstream_xchacha20poly1305_keygen() {
        return new CryptographyKey(
            await this.backend.randombytes_buf(this.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES)
        );
    }

    /**
     * Calculate a fast hash for short inputs.
     *
     * Algorithm: SipHash-2-4
     *
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_shorthash(message, key) {
        await this.ensureLoaded();
        return await this.backend.crypto_shorthash(message, key);
    }

    /**
     * @return {Promise<CryptographyKey>}
     */
    async crypto_shorthash_keygen() {
        return new CryptographyKey(
            await this.backend.randombytes_buf(this.CRYPTO_SHORTHASH_KEYBYTES)
        );
    }

    /**
     * Returns a signed message.
     *
     * @param {string|Buffer} message,
     * @param {Ed25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign(message, secretKey) {
        await this.ensureLoaded();
        if (!(secretKey instanceof Ed25519SecretKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519SecretKey');
        }
        return this.backend.crypto_sign(message, secretKey);
    }

    /**
     * Given a signed message, verify the Ed25519 signature. If it matches, return the
     * bare message (no signature).
     *
     * @param {string|Buffer} message,
     * @param {Ed25519PublicKey} publicKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign_open(message, publicKey) {
        await this.ensureLoaded();
        if (!(publicKey instanceof Ed25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519PublicKey');
        }
        return this.backend.crypto_sign_open(message, publicKey);
    }

    /**
     * Returns the Ed25519 signature of the message, for the given secret key.
     *
     * @param {string|Buffer} message,
     * @param {Ed25519SecretKey} secretKey
     * @return {Promise<Buffer>}
     */
    async crypto_sign_detached(message, secretKey) {
        await this.ensureLoaded();
        if (!(secretKey instanceof Ed25519SecretKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519SecretKey');
        }
        return this.backend.crypto_sign_detached(message, secretKey);
    }

    /**
     * Returns true if the Ed25519 signature is valid for a given message and public key.
     *
     * @param {string|Buffer} message,
     * @param {Ed25519PublicKey} publicKey
     * @param {Buffer} signature
     * @return {Promise<boolean>}
     */
    async crypto_sign_verify_detached(message, publicKey, signature) {
        await this.ensureLoaded();
        if (!(publicKey instanceof Ed25519PublicKey)) {
            throw new TypeError('Argument 2 must be an instance of Ed25519PublicKey');
        }
        return this.backend.crypto_sign_verify_detached(message, publicKey, signature);
    }

    /**
     * Extract the secret key from an Ed25519 keypair object.
     *
     * @param {CryptographyKey} keypair
     * @return {Promise<Ed25519SecretKey>}
     */
    async crypto_sign_secretkey(keypair) {
        if (keypair.getLength() !== 96) {
            throw new SodiumError('Keypair must be 96 bytes');
        }
        return new Ed25519SecretKey(
            await Util.toBuffer(
                keypair.getBuffer().slice(0, 64)
            )
        );
    }

    /**
     * Extract the public key from an Ed25519 keypair object.
     *
     * @param {CryptographyKey} keypair
     * @return {Promise<Ed25519PublicKey>}
     */
    async crypto_sign_publickey(keypair) {
        if (keypair.getLength() !== 96) {
            throw new SodiumError('Keypair must be 96 bytes');
        }
        return new Ed25519PublicKey(
            keypair.getBuffer().slice(64, 96)
        );
    }

    /**
     * Generate an Ed25519 keypair object.
     *
     * @return {Promise<CryptographyKey>}
     */
    async crypto_sign_keypair() {
        await this.ensureLoaded();
        return this.backend.crypto_sign_keypair();
    }

    /**
     * Obtain a birationally equivalent X25519 secret key,
     * given an Ed25519 secret key.
     *
     * @param {Ed25519SecretKey} sk
     * @return {Promise<X25519SecretKey>}
     */
    async crypto_sign_ed25519_sk_to_curve25519(sk) {
        await this.ensureLoaded();
        return new X25519SecretKey(
            await this.backend.crypto_sign_ed25519_sk_to_curve25519(sk)
        );
    }

    /**
     * Obtain a birationally equivalent X25519 public key,
     * given an Ed25519 public key.
     *
     * @param {Ed25519PublicKey} pk
     * @return {Promise<X25519PublicKey>}
     */
    async crypto_sign_ed25519_pk_to_curve25519(pk) {
        await this.ensureLoaded();
        return new X25519PublicKey(
            await this.backend.crypto_sign_ed25519_pk_to_curve25519(pk)
        );
    }

    /**
     * @param {number} length
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_stream(length, nonce, key) {
        await this.ensureLoaded();
        return this.backend.crypto_stream(length, nonce, key);
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_stream_xor(plaintext, nonce, key) {
        await this.ensureLoaded();
        return this.backend.crypto_stream_xor(plaintext, nonce, key);
    }

    /**
     * Returns a buffer filled with random bytes.
     *
     * @param {number} num
     * @return {Promise<Buffer>}
     */
    async randombytes_buf(num) {
        await this.ensureLoaded();
        return await this.backend.randombytes_buf(num);
    }

    /**
     * Generate an integer between 0 and upperBound (non-inclusive).
     *
     * For example, randombytes_uniform(10) returns an integer between 0 and 9.
     *
     * @param {number} upperBound
     * @return {Promise<number>}
     */
    async randombytes_uniform(upperBound) {
        await this.ensureLoaded();
        return this.backend.randombytes_uniform(upperBound);
    }

    /**
     * Add two buffers (little-endian). Returns the value.
     *
     * @param {Buffer} val
     * @param {Buffer} addv
     * @return {Promise<Buffer>}
     */
    async sodium_add(val, addv) {
        await this.ensureLoaded();
        return await this.backend.sodium_add(
            await Util.toBuffer(val),
            await Util.toBuffer(addv)
        );
    }

    /**
     * Compare two buffers in constant time.
     *
     * Returns -1 if b1 is less than b2.
     * Returns  1 if b1 is greater than b2.
     * Returns  0 if b1 is equal to b2.
     *
     * @param {Buffer} b1
     * @param {Buffer} b2
     * @return {Promise<number>}
     */
    async sodium_compare(b1, b2) {
        await this.ensureLoaded();
        return this.backend.sodium_compare(b1, b2);
    }

    /**
     * Increment a buffer (little endian). Overwrites the buffer in-place.
     *
     * @param {Buffer} buf
     * @return {Promise<Buffer>}
     */
    async sodium_increment(buf) {
        await this.ensureLoaded();
        return this.backend.sodium_increment(buf);
    }

    /**
     * Returns true if the buffer is zero.
     *
     * @param {Buffer} buf
     * @param {number} len
     * @return {Promise<Buffer>}
     */
    async sodium_is_zero(buf, len) {
        await this.ensureLoaded();
        return this.backend.sodium_is_zero(buf, len);
    }

    /**
     * Timing-safe buffer comparison.
     *
     * @param {Buffer} b1
     * @param {Buffer} b2
     * @return {Promise<boolean>}
     */
    async sodium_memcmp(b1, b2) {
        await this.ensureLoaded();
        return this.backend.sodium_memcmp(b1, b2);
    }

    /**
     * Zero out a buffer. Overwrites the buffer in-place.
     *
     * @param {Buffer} buf
     * @return {Promise<void>}
     */
    async sodium_memzero(buf) {
        await this.ensureLoaded();
        await this.backend.sodium_memzero(buf);
    }

    /**
     * Pad a string.
     *
     * @param {string|Buffer} buf
     * @param {number} blockSize
     * @return {Promise<Buffer>}
     */
    async sodium_pad(buf, blockSize) {
        await this.ensureLoaded();
        return this.backend.sodium_pad(buf, blockSize);
    }

    /**
     * Unpad a string.
     *
     * @param {string|Buffer} buf
     * @param {number} blockSize
     * @return {Promise<Buffer>}
     */
    async sodium_unpad(buf, blockSize) {
        await this.ensureLoaded();
        return this.backend.sodium_unpad(buf, blockSize);
    }
}

module.exports = SodiumPlus;
