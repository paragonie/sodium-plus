const assert = require('assert');
const crypto = require('crypto')
const { describe, it } = require('mocha');
const { expect } = require('chai');
const {
    CryptographyKey,
    Ed25519PublicKey,
    Ed25519SecretKey,
    X25519PublicKey,
    X25519SecretKey
} = require('../index');

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

        let ed25519sk = Ed25519SecretKey.from(
            '88c6102ed8b3278ae7e95ebcd4ed3f1a513d2fd3c1a88f5ecbda5f95209ce709' +
            '324095af3d25e0f205d1a1297d01e810940063d05fc247d2042f6fc2f98a55c2',
            'hex'
        );
        expect(ed25519sk instanceof Ed25519SecretKey).to.be.equals(true);
        let ed25519pk = Ed25519PublicKey.from(
            '324095af3d25e0f205d1a1297d01e810940063d05fc247d2042f6fc2f98a55c2',
            'hex'
        );
        expect(ed25519pk instanceof Ed25519PublicKey).to.be.equals(true);
        let x25519sk = X25519SecretKey.from(
            'fcb38e648f61e145c96be1a89776754b0a2e28ba57d3024ecae892dc5d93ec26',
            'hex'
        );
        expect(x25519sk instanceof X25519SecretKey).to.be.equals(true);
        let x25519pk = X25519PublicKey.from(
            '81149890dc709032327ab8d2628df8c0c8163f59bbb92a6fc3a83cb34864d503',
            'hex'
        );
        expect(x25519pk instanceof X25519PublicKey).to.be.equals(true);
    });
});
