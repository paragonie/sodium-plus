const assert = require('assert');
const crypto = require('crypto')
const { describe, it } = require('mocha');
const { expect } = require('chai');
const { CryptographyKey } = require('../index');

let sodium;
describe('CryptographyKey', () => {
    it('Internal buffer is hidden from stack traces and iterators', async () => {
        let bytes = crypto.randomBytes(32);
        let key = new CryptographyKey(bytes);
        assert(Object.keys(key).length === 0, 'There should be no keys when you dump an object!');
        expect(bytes.toString('hex')).to.be.equals(key.getBuffer().toString('hex'));
    });

    it('from()', async () => {
        let key = CryptographyKey.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
        expect(key.getBuffer().toString('hex')).to.be.equals('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    });
});
