const CryptographyKey = require('../cryptography-key');

class Ed25519PublicKey extends CryptographyKey {
    constructor(buf) {
        if (buf.length !== 32) {
            console.log(buf.length);
            throw new Error('Ed25519 public keys must be 32 bytes long');
        }
        super(buf);
        this.keyType = 'ed25519';
        this.publicKey = true;
    }

    isEd25519Key() {
        return true;
    }

    isPublicKey() {
        return true;
    }
}

module.exports = Ed25519PublicKey;
