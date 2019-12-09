const CryptographyKey = require('../cryptography-key');

class Ed25519SecretKey extends CryptographyKey {
    constructor(buf) {
        if (buf.length !== 64) {
            throw new Error('Ed25519 secret keys must be 64 bytes long');
        }
        super(buf);
        this.keyType = 'ed25519';
        this.publicKey = false;
    }

    /**
     * @return {Ed25519SecretKey}
     */
    static from() {
        return new Ed25519SecretKey(Buffer.from(...arguments));
    }

    isEd25519Key() {
        return true;
    }

    isPublicKey() {
        return false;
    }
}

module.exports = Ed25519SecretKey;