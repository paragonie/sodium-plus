const _sodium = require('libsodium-wrappers');
const Backend = require('../backend');
const CryptographyKey = require('../cryptography-key');
const Polyfill = require('../polyfill');
const Util = require('../util');
const SodiumError = require('../sodium-error');
const toBuffer = require('typedarray-to-buffer');
/* istanbul ignore if */
if (typeof (Buffer) === 'undefined') {
    let Buffer = require('buffer/').Buffer;
}

/* istanbul ignore next */
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
        const obj = this.sodium.crypto_box_keypair();
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
            return Util.toBuffer(
                this.sodium.crypto_generichash(
                    outputLength,
                    await Util.toBuffer(message),
                    key.getBuffer()
                )
            );
        }
        return Util.toBuffer(
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
        return Util.toBuffer(
            this.sodium.crypto_generichash_final(state, outputLength)
        );
    }

    /**
     * @param {X25519PublicKey} clientPublicKey
     * @param {X25519SecretKey} clientSecretKey
     * @param {X25519PublicKey} serverPublicKey
     * @return {Promise<CryptographyKey[]>}
     */
    async crypto_kx_client_session_keys(clientPublicKey, clientSecretKey, serverPublicKey) {
        const gen = this.sodium.crypto_kx_client_session_keys(
            clientPublicKey.getBuffer(),
            clientSecretKey.getBuffer(),
            serverPublicKey.getBuffer(),
        );
        return [
            new CryptographyKey(await Util.toBuffer(gen.sharedRx)),
            new CryptographyKey(await Util.toBuffer(gen.sharedTx))
        ];
    }

    /**
     * @param {X25519PublicKey} serverPublicKey
     * @param {X25519SecretKey} serverSecretKey
     * @param {X25519PublicKey} clientPublicKey
     * @return {Promise<CryptographyKey[]>}
     */
    async crypto_kx_server_session_keys(serverPublicKey, serverSecretKey, clientPublicKey) {
        const gen = this.sodium.crypto_kx_server_session_keys(
            serverPublicKey.getBuffer(),
            serverSecretKey.getBuffer(),
            clientPublicKey.getBuffer(),
        );
        return [
            new CryptographyKey(await Util.toBuffer(gen.sharedRx)),
            new CryptographyKey(await Util.toBuffer(gen.sharedTx))
        ];
    }

    /**
     * @param {number} length
     * @param {number} subKeyId
     * @param {string|Buffer} context
     * @param {CryptographyKey} key
     * @return {Promise<CryptographyKey>}
     */
    async crypto_kdf_derive_from_key(length, subKeyId, context, key) {
        return new CryptographyKey(
            await Util.toBuffer(
                this.sodium.crypto_kdf_derive_from_key(
                    length,
                    subKeyId | 0,
                    context,
                    key.getBuffer()
                )
            )
        );
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_onetimeauth(message, key) {
        if (typeof this.sodium.crypto_onetimeauth === 'undefined') {
            return Polyfill.crypto_onetimeauth(
                await Util.toBuffer(message),
                key
            );
        }
        return this.sodium.crypto_onetimeauth(
            await Util.toBuffer(message),
            key.getBuffer()
        );
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @param {Buffer} tag
     * @return {Promise<boolean>}
     */
    async crypto_onetimeauth_verify(message, key, tag) {
        if (typeof this.sodium.crypto_onetimeauth_verify === 'undefined') {
            return Polyfill.crypto_onetimeauth_verify(
                await Util.toBuffer(message),
                key,
                tag
            );
        }
        return this.sodium.crypto_onetimeauth_verify(
            tag,
            await Util.toBuffer(message),
            key.getBuffer()
        );
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
    async crypto_pwhash(length, password, salt, opslimit, memlimit, algorithm) {
        return Util.toBuffer(
            this.sodium.crypto_pwhash(
                length,
                await Util.toBuffer(password),
                await Util.toBuffer(salt),
                opslimit,
                memlimit,
                algorithm
            )
        );
    }

    /**
     * @param {string|Buffer} password
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<string>}
     */
    async crypto_pwhash_str(password, opslimit, memlimit) {
        return (await Util.toBuffer(
            this.sodium.crypto_pwhash_str(
                await Util.toBuffer(password),
                opslimit,
                memlimit
            ))
        ).toString('utf-8');
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} hash
     * @return {Promise<boolean>}
     */
    async crypto_pwhash_str_verify(password, hash) {
        return this.sodium.crypto_pwhash_str_verify(
            hash.toString('utf-8'),
            await Util.toBuffer(password)
        );
    }

    /**
     * @param {string|Buffer} hash
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<boolean>}
     */
    async crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit) {
        if (typeof (this.sodium.crypto_pwhash_str_needs_rehash) !== 'function') {
            return await Polyfill.crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit);
        }
        return this.sodium.crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit);
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
        return Util.toBuffer(
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
        return Util.toBuffer(
            this.sodium.crypto_secretbox_open_easy(
                await Util.toBuffer(ciphertext),
                nonce,
                key.getBuffer()
            )
        );
    }

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_shorthash(message, key) {
        return Util.toBuffer(
            this.sodium.crypto_shorthash(
                await Util.toBuffer(message),
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
        return Util.toBuffer(
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
        return Util.toBuffer(
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
        return Util.toBuffer(
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
        const obj = this.sodium.crypto_sign_keypair();
        return new CryptographyKey(
            Buffer.concat([
                await Util.toBuffer(obj.privateKey),
                await Util.toBuffer(obj.publicKey)
            ])
        );
    }

    /**
     * @param {Buffer} seed
     * @return {Promise<CryptographyKey>}
     */
    async crypto_sign_seed_keypair(seed) {
        const obj = this.sodium.crypto_sign_seed_keypair(seed);
        return new CryptographyKey(
            Buffer.concat([
                await Util.toBuffer(obj.privateKey),
                await Util.toBuffer(obj.publicKey)
            ])
        );
    }

    /**
     * @param {Ed25519SecretKey} sk
     * @return {Promise<Buffer>}
     */
    async crypto_sign_ed25519_sk_to_curve25519(sk) {
        return Util.toBuffer(
            this.sodium.crypto_sign_ed25519_sk_to_curve25519(sk.getBuffer())
        );
    }

    /**
     * @param {Ed25519PublicKey} pk
     * @return {Promise<Buffer>}
     */
    async crypto_sign_ed25519_pk_to_curve25519(pk) {
        return Util.toBuffer(
            this.sodium.crypto_sign_ed25519_pk_to_curve25519(pk.getBuffer())
        );
    }


    /**
     * @param {number} length
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_stream(length, nonce, key) {
        if (typeof (this.sodium.crypto_stream_xor) === 'undefined') {
            return Polyfill.crypto_stream_xor(
                Buffer.alloc(length, 0),
                await Util.toBuffer(nonce),
                key
            );
        }
        return this.sodium.crypto_stream(
            length,
            await Util.toBuffer(nonce),
            key.getBuffer()
        );
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    async crypto_stream_xor(plaintext, nonce, key) {
        if (typeof (this.sodium.crypto_stream_xor) === 'undefined') {
            return Polyfill.crypto_stream_xor(
                await Util.toBuffer(plaintext),
                await Util.toBuffer(nonce),
                key
            )
        }
        return this.sodium.crypto_stream_xor(
            await Util.toBuffer(plaintext),
            await Util.toBuffer(nonce),
            key.getBuffer()
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
     * @param {CryptographyKey} key
     * @return {Promise<array>} [state, header]
     */
    async crypto_secretstream_xchacha20poly1305_init_push(key) {
        const res = this.sodium.crypto_secretstream_xchacha20poly1305_init_push(key.getBuffer());
        return [res.state, await Util.toBuffer(res.header)];
    }

    /**
     * @param {Buffer} header
     * @param {CryptographyKey} key
     * @return {Promise<*>} Returns the opaque state object
     */
    async crypto_secretstream_xchacha20poly1305_init_pull(header, key) {
        if (header.length !== this.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new SodiumError(`Header must be ${this.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES} bytes long`);
        }
        return this.sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key.getBuffer());
    }

    /**
     * @param {*} state
     * @param {string|Buffer} message
     * @param {string|Buffer} ad
     * @param {number} tag
     * @return {Promise<Buffer>}
     */
    async crypto_secretstream_xchacha20poly1305_push(state, message, ad = '', tag = 0) {
        return Util.toBuffer(
            this.sodium.crypto_secretstream_xchacha20poly1305_push(
                state,
                await Util.toBuffer(message),
                ad.length > 0 ? (await Util.toBuffer(ad)) : null,
                tag
            )
        );
    }

    /**
     * @param {*} state
     * @param {Buffer} ciphertext
     * @param {string|Buffer} ad
     * @param {number} tag
     * @return {Promise<Buffer>}
     */
    async crypto_secretstream_xchacha20poly1305_pull(state, ciphertext, ad = '', tag = 0) {
        if (ciphertext.length < this.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES) {
            throw new SodiumError('Invalid ciphertext size');
        }
        const out = this.sodium.crypto_secretstream_xchacha20poly1305_pull(
            state,
            await Util.toBuffer(ciphertext),
            ad.length > 0 ? (await Util.toBuffer(ad)) : null,
            tag
        );
        if (tag !== out.tag) {
            throw new SodiumError(`Invalid tag (Given: ${tag}; Expected: ${out.tag})`);
        }
        return Util.toBuffer(out.message);
    }

    /**
     * @param {*} state
     * @return {Promise<void>}
     */
    async crypto_secretstream_xchacha20poly1305_rekey(state) {
        this.sodium.crypto_secretstream_xchacha20poly1305_rekey(state);
    }

    /**
     * @param {number} number
     * @return {Promise<Buffer>}
     */
    async randombytes_buf(number) {
        return Util.toBuffer(await this.sodium.randombytes_buf(number));
    }

    /**
     * @param {number} upperBound
     * @return {Promise<number>}
     */
    async randombytes_uniform(upperBound) {
        return this.sodium.randombytes_uniform(upperBound);
    }

    /**
     * @param {Uint8Array} val
     * @param {Uint8Array} addv
     * @return {Promise<Buffer>}
     */
    async sodium_add(val, addv) {
        const buf = await Util.cloneBuffer(val);
        this.sodium.add(buf, addv);
        return buf;
    }

    /**
     * @param {Buffer} buf
     * @return {Promise<string>}
     */
    async sodium_bin2hex(buf) {
        return this.sodium.to_hex(buf);
    }

    /**
     * @param {Buffer} b1
     * @param {Buffer} b2
     * @return {Promise<number>}
     */
    async sodium_compare(b1, b2) {
        return this.sodium.compare(b1, b2);
    }

    /**
     * @param {Buffer|string} encoded
     * @return {Promise<Buffer>}
     */
    async sodium_hex2bin(encoded) {
        return Buffer.from(this.sodium.from_hex(encoded));
    }

    /**
     * @param {Buffer} buf
     * @return {Promise<Buffer>}
     */
    async sodium_increment(buf) {
        return this.sodium.increment(buf);
    }

    /**
     * @param {Buffer} buf
     * @param {number} len
     * @return {Promise<Buffer>}
     */
    async sodium_is_zero(buf, len) {
        return this.sodium.is_zero(buf, len);
    }

    /**
     * @param {Buffer} b1
     * @param {Buffer} b2
     * @return {Promise<boolean>}
     */
    async sodium_memcmp(b1, b2) {
        return this.sodium.memcmp(b1, b2);
    }

    /**
     * @param {Buffer} buf
     * @return {Promise<void>}
     */
    async sodium_memzero(buf) {
        this.sodium.memzero(buf);
    }


    /**
     *
     * @param {string|Buffer} buf
     * @param {number} blockSize
     * @return {Promise<Buffer>}
     */
    async sodium_pad(buf, blockSize) {
        return Util.toBuffer(
            this.sodium.pad(await Util.toBuffer(buf), blockSize)
        );
    }

    /**
     *
     * @param {string|Buffer} buf
     * @param {number} blockSize
     * @return {Promise<Buffer>}
     */
    async sodium_unpad(buf, blockSize) {
        return Util.toBuffer(this.sodium.unpad(buf, blockSize));
    }
};
