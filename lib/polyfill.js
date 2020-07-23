"use strict";
const crypto = require('crypto');
const Poly1305 = require('poly1305-js');
const Util = require('./util');
const XSalsa20 = require('xsalsa20');

/* istanbul ignore if */
if (typeof (Buffer) === 'undefined') {
    let Buffer = require('buffer/').Buffer;
}

module.exports = class SodiumPolyfill {

    /**
     * @param {string|Buffer} message
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    static async crypto_onetimeauth(message, key) {
        return Poly1305.onetimeauth(
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
    static async crypto_onetimeauth_verify(message, key, tag) {
        return Poly1305.onetimeauth_verify(
            await Util.toBuffer(message),
            key.getBuffer(),
            await Util.toBuffer(tag)
        );
    }

    /**
     * @param {string|Buffer} plaintext
     * @param {Buffer} nonce
     * @param {CryptographyKey} key
     * @return {Promise<Buffer>}
     */
    static async crypto_stream_xor(plaintext, nonce, key) {
        const stream = XSalsa20(nonce, key.getBuffer());
        const output = stream.update(plaintext);
        stream.finalize();
        return Util.toBuffer(output);
    }

    /**
     * Polyfill crypto_pwhash_str_needs_rehash() for bindings that don't
     * include this (somewhat new) helper function.
     *
     * @param {string|Buffer} hash
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<boolean>}
     */
    static async crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit) {
        const pwhash = (await Util.toBuffer(hash)).toString('utf-8');
        const pieces = pwhash.split('$');
        const expect = 'm=' + (memlimit >> 10) + ',t=' + opslimit + ',p=1';
        if (expect.length !== pieces[3].length) {
            return true;
        }
        return !crypto.timingSafeEqual(
            await Util.toBuffer(expect),
            await Util.toBuffer(pieces[3])
        );
    }
};
