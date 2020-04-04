"use strict";

/* istanbul ignore if */
if (typeof (Buffer) === 'undefined') {
    let Buffer = require('buffer/').Buffer;
}

const arrayToBuffer = require('typedarray-to-buffer');

module.exports = class Util
{
    static async cloneBuffer(buf) {
        return Buffer.from(buf);
    }

    /**
     * Define the sodium constants
     *
     * @param {object} anyobject
     * @return {object}
     */
    static populateConstants(anyobject) {
        anyobject.LIBRARY_VERSION_MAJOR = 10;
        anyobject.LIBRARY_VERSION_MINOR = 2;
        anyobject.VERSION_STRING = '1.0.17';
        anyobject.BASE64_VARIANT_ORIGINAL = 1;
        anyobject.BASE64_VARIANT_ORIGINAL_NO_PADDING = 3;
        anyobject.BASE64_VARIANT_URLSAFE = 5;
        anyobject.BASE64_VARIANT_URLSAFE_NO_PADDING = 7;
        anyobject.CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;
        anyobject.CRYPTO_AEAD_AES256GCM_NSECBYTES = 0;
        anyobject.CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;
        anyobject.CRYPTO_AEAD_AES256GCM_ABYTES = 16;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES = 0;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES = 32;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES = 0;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES = 12;
        anyobject.CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = 16;
        anyobject.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES = 32;
        anyobject.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES = 0;
        anyobject.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24;
        anyobject.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES = 16;
        anyobject.CRYPTO_AUTH_BYTES = 32;
        anyobject.CRYPTO_AUTH_KEYBYTES = 32;
        anyobject.CRYPTO_BOX_SEALBYTES = 16;
        anyobject.CRYPTO_BOX_SECRETKEYBYTES = 32;
        anyobject.CRYPTO_BOX_PUBLICKEYBYTES = 32;
        anyobject.CRYPTO_BOX_KEYPAIRBYTES = 64;
        anyobject.CRYPTO_BOX_MACBYTES = 16;
        anyobject.CRYPTO_BOX_NONCEBYTES = 24;
        anyobject.CRYPTO_BOX_SEEDBYTES = 32;
        anyobject.CRYPTO_KDF_BYTES_MIN = 16;
        anyobject.CRYPTO_KDF_BYTES_MAX = 64;
        anyobject.CRYPTO_KDF_CONTEXTBYTES = 8;
        anyobject.CRYPTO_KDF_KEYBYTES = 32;
        anyobject.CRYPTO_KX_BYTES = 32;
        anyobject.CRYPTO_KX_PRIMITIVE = 'x25519blake2b';
        anyobject.CRYPTO_KX_SEEDBYTES = 32;
        anyobject.CRYPTO_KX_KEYPAIRBYTES = 64;
        anyobject.CRYPTO_KX_PUBLICKEYBYTES = 32;
        anyobject.CRYPTO_KX_SECRETKEYBYTES = 32;
        anyobject.CRYPTO_KX_SESSIONKEYBYTES = 32;
        anyobject.CRYPTO_GENERICHASH_BYTES = 32;
        anyobject.CRYPTO_GENERICHASH_BYTES_MIN = 16;
        anyobject.CRYPTO_GENERICHASH_BYTES_MAX = 64;
        anyobject.CRYPTO_GENERICHASH_KEYBYTES = 32;
        anyobject.CRYPTO_GENERICHASH_KEYBYTES_MIN = 16;
        anyobject.CRYPTO_GENERICHASH_KEYBYTES_MAX = 64;
        anyobject.CRYPTO_GENERICHASH_STATEBYTES = 384;
        anyobject.CRYPTO_PWHASH_SALTBYTES = 16;
        anyobject.CRYPTO_PWHASH_STRPREFIX = '$argon2id$';
        anyobject.CRYPTO_PWHASH_ALG_ARGON2I13 = 1;
        anyobject.CRYPTO_PWHASH_ALG_ARGON2ID13 = 2;
        anyobject.CRYPTO_PWHASH_ALG_DEFAULT = anyobject.CRYPTO_PWHASH_ALG_ARGON2ID13;
        anyobject.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 2;
        anyobject.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 67108864;
        anyobject.CRYPTO_PWHASH_OPSLIMIT_MODERATE = 3;
        anyobject.CRYPTO_PWHASH_MEMLIMIT_MODERATE = 268435456;
        anyobject.CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = 4;
        anyobject.CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = 1073741824;
        anyobject.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES = 32;
        anyobject.CRYPTO_SCALARMULT_BYTES = 32;
        anyobject.CRYPTO_SCALARMULT_SCALARBYTES = 32;
        anyobject.CRYPTO_SHORTHASH_BYTES = 8;
        anyobject.CRYPTO_SHORTHASH_KEYBYTES = 16;
        anyobject.CRYPTO_SECRETBOX_KEYBYTES = 32;
        anyobject.CRYPTO_SECRETBOX_MACBYTES = 16;
        anyobject.CRYPTO_SECRETBOX_NONCEBYTES = 24;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_STATEBYTES = 52;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES = 17;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES = 24;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES = 32;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH = 0;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PULL = 1;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY = 2;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL = 3;
        anyobject.CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX = 0x3fffffff80;
        anyobject.CRYPTO_SIGN_BYTES = 64;
        anyobject.CRYPTO_SIGN_SEEDBYTES = 32;
        anyobject.CRYPTO_SIGN_PUBLICKEYBYTES = 32;
        anyobject.CRYPTO_SIGN_SECRETKEYBYTES = 64;
        anyobject.CRYPTO_SIGN_KEYPAIRBYTES = 96;
        anyobject.CRYPTO_STREAM_KEYBYTES = 32;
        anyobject.CRYPTO_STREAM_NONCEBYTES = 24;
        return anyobject;
    }

    /**
     * Coerce input to a Buffer, throwing a TypeError if it cannot be coerced.
     *
     * @param {string|Buffer|Uint8Array|Promise<Buffer>} stringOrBuffer
     * @returns {Buffer}
     */
    static async toBuffer(stringOrBuffer)
    {
        if (Buffer.isBuffer(stringOrBuffer)) {
            return stringOrBuffer;
        } else if (stringOrBuffer === null) {
            return null;
        } else if (typeof(stringOrBuffer) === 'string') {
            return Buffer.from(stringOrBuffer, 'binary');
        } else if (stringOrBuffer instanceof Uint8Array) {
            return arrayToBuffer(stringOrBuffer);
        } else if (stringOrBuffer instanceof Promise) {
            return await stringOrBuffer;
        } else {
            throw new TypeError('Invalid type; string or buffer expected');
        }
    }
};
