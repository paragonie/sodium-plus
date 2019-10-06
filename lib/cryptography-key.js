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

    /**
     * @return {Buffer}
     */
    getBuffer() {
        return this.buffer;
    }
};
