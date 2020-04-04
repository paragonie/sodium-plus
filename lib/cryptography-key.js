"use strict";

/* istanbul ignore if */
if (typeof (Buffer) === 'undefined') {
    let Buffer = require('buffer/').Buffer;
}
module.exports = class CryptographyKey {
    /**
     * Note: We use Object.defineProperty() to hide the buffer inside of the
     * CryptographyKey object to prevent accidental leaks.
     *
     * @param {Buffer} buf
     */
    constructor(buf) {
        if (!Buffer.isBuffer(buf)) {
            throw new TypeError('Argument 1 must be an instance of Buffer.');
        }
        Object.defineProperty(this, 'buffer', {
            enumerable: false,
            value: buf.slice()
        });
    }

    /**
     * @return {CryptographyKey}
     */
    static from() {
        return new CryptographyKey(Buffer.from(...arguments));
    }

    /**
     * @return {boolean}
     */
    isEd25519Key() {
        return false;
    }

    /**
     * @return {boolean}
     */
    isX25519Key() {
        return false;
    }

    /**
     * @return {boolean}
     */
    isPublicKey() {
        return false;
    }

    /**
     * @return {Number}
     */
    getLength() {
        return this.buffer.length;
    }

    /**
     * @return {Buffer}
     */
    getBuffer() {
        return this.buffer;
    }

    /**
     * @param {string} encoding
     */
    toString(encoding = 'utf-8') {
        /* istanbul ignore if */
        return this.getBuffer().toString(encoding);
    }

    /**
     * @return {Buffer}
     */
    slice() {
        return this.buffer.slice(...arguments);
    }
};
