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

    /**
     * @return {X25519SecretKey}
     */
    static from() {
        return new X25519SecretKey(Buffer.from(...arguments));
    }

    isX25519Key() {
        return true;
    }

    isPublicKey() {
        return false;
    }
}

module.exports = X25519SecretKey;
