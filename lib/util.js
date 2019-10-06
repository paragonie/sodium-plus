"use strict";

const crypto = require('crypto');
const arrayToBuffer = require('typedarray-to-buffer');

module.exports = class Util
{
    static async cloneBuffer(buf) {
        return Buffer.from(buf);
    }

    /**
     * Gets the string representation of a Buffer.
     *
     * @param {Buffer} buffer
     * @returns {string}
     */
    static fromBuffer(buffer)
    {
        if (!Buffer.isBuffer(buffer)) {
            throw new TypeError('Invalid type; string or buffer expected');
        }
        return buffer.toString('binary');
    }

    /**
     * Get the digest size based on a hash function name.
     *
     * @param {string} algo
     * @return {Number}
     */
    static hashDigestLength(algo)
    {
        if (algo === 'sha256') {
            return 32;
        } else if (algo === 'sha384') {
            return 48;
        } else if (algo === 'sha512') {
            return 64;
        } else if (algo === 'sha224') {
            return 24;
        }
        let hasher = crypto.createHash(algo);
        hasher.update('');
        let digest = hasher.digest();
        return digest.length;
    }

    /**
     * Compare two strings without timing leaks.
     *
     * @param {string|Buffer} a
     * @param {string|Buffer} b
     * @returns {boolean}
     */
    static async hashEquals(a, b)
    {
        return crypto.timingSafeEqual(
            await Util.toBuffer(a),
            await Util.toBuffer(b)
        );
    }

    /**
     *
     * @param {Buffer} nonce
     * @param {number} amount
     * @return {Promise<Buffer>}
     */
    static async increaseCtrNonce(nonce, amount = 1)
    {
        let outNonce = Buffer.alloc(16, 0);
        nonce.copy(outNonce, 0, 0, 16);
        let c = amount;
        let x;
        for (let i = 15; i >= 0; i--) {
            x = outNonce[i] + c;
            c = x >>> 8;
            outNonce[i] = x & 0xff;
        }
        return outNonce;
    }

    /**
     * Node.js only supports 32-bit numbers so we discard the top 4 bytes.
     *
     * @param {Buffer} buf
     * @return {Number}
     */
    static load64_le(buf)
    {
        return buf.readInt32LE(0);
    }

    /**
     * Pack chunks together for feeding into HMAC.
     *
     * @param {Buffer[]} pieces
     * @return Buffer
     */
    static pack(pieces)
    {
        let output = Util.store32_le(pieces.length);
        let piece;
        let pieceLen;
        for (let i = 0; i < pieces.length; i++) {
            piece = pieces[i];
            pieceLen = Util.store64_le(piece.length);
            output = Buffer.concat([output, pieceLen, piece]);
        }
        return output;
    }

    /**
     * Store a 32-bit integer as a buffer of length 4
     *
     * @param {Number} num
     * @return {Buffer}
     */
    static store32_le(num)
    {
        let result = Buffer.alloc(4, 0);
        result[0] = num & 0xff;
        result[1] = (num >>>  8) & 0xff;
        result[2] = (num >>> 16) & 0xff;
        result[3] = (num >>> 24) & 0xff;
        return result;
    }

    /**
     * JavaScript only supports 32-bit integers, so we're going to
     * zero-fill the rightmost bytes.
     *
     * @param {Number} num
     * @return {Buffer}
     */
    static store64_le(num)
    {
        let result = Buffer.alloc(8, 0);
        result[0] = num & 0xff;
        result[1] = (num >>>  8) & 0xff;
        result[2] = (num >>> 16) & 0xff;
        result[3] = (num >>> 24) & 0xff;
        return result;
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
