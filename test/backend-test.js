const { describe, it } = require('mocha');
const { expect } = require('chai');
const { SodiumPlus, X25519SecretKey, X25519PublicKey } = require('../index');

let sodium;
describe('Backend', () => {
    it('crypto_box_keypair_from_secretkey_and_publickey', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        let a = Buffer.alloc(32);
        let b = Buffer.alloc(32);
        let c = Buffer.alloc(31);

        let d = await sodium.crypto_box_keypair_from_secretkey_and_publickey(
            new X25519SecretKey(a),
            new X25519PublicKey(b)
        );
        expect(64).to.be.equal(d.buffer.length);

        expect(() => {
            sodium.crypto_box_keypair_from_secretkey_and_publickey(
                new X25519SecretKey(c),
                new X25519PublicKey(b)
            )
                .then(() => {})
                .catch((e) => { throw e });
        }).to.throw('X25519 secret keys must be 32 bytes long');

        expect(() => {
            sodium.crypto_box_keypair_from_secretkey_and_publickey(
                new X25519SecretKey(a),
                new X25519PublicKey(c)
            )
                .then(() => {})
                .catch((e) => { throw e });
        }).to.throw('X25519 public keys must be 32 bytes long');
    });
});