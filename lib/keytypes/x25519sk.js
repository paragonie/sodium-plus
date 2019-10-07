const CryptographyKey = require('../cryptography-key');

class X25519SecretKey extends CryptographyKey {
    constructor(buf) {
        if (buf.length !== 32) {
            throw new Error('X25519 secret keys must be 32 bytes long');
        }
        super(buf);
        this.keyType = 'x25519';
        this.publicKey = false;
    }

    isX25519Key() {
        return true;
    }

    isPublicKey() {
        return false;
    }
}

module.exports = X25519SecretKey;
