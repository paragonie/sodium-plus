module.exports = class CryptographyKey {
    constructor(buf) {
        if (!Buffer.isBuffer(buf)) {
            throw new TypeError('Argument 1 must be an instance of Buffer.');
        }
        Object.defineProperty(this, 'buffer', {
            enumerable: false,
            value: buf
        });
    }

    static from() {
        return new CryptographyKey(Buffer.from(...arguments));
    }

    isEd25519Key() {
        return false;
    }

    isX25519Key() {
        return false;
    }

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
     * @return {Buffer}
     */
    slice() {
        return this.buffer.slice(...arguments);
    }
};
