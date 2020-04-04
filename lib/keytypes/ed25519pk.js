const CryptographyKey = require('../cryptography-key');

class Ed25519PublicKey extends CryptographyKey {
    constructor(buf) {
        if (buf.length !== 32) {
            throw new Error('Ed25519 public keys must be 32 bytes long');
        }
        super(buf);
        this.keyType = 'ed25519';
        this.publicKey = true;
    }
    /**
     * @return {Ed25519PublicKey}
     */
    static from() {
        return new Ed25519PublicKey(Buffer.from(...arguments));
    }

    isEd25519Key() {
        return true;
    }

    isPublicKey() {
        return true;
    }
}

module.exports = Ed25519PublicKey;
