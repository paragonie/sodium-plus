const CryptographyKey = require('../cryptography-key');

class X25519PublicKey extends CryptographyKey {
    constructor(buf) {
        if (buf.length !== 32) {
            throw new Error('X25519 public keys must be 32 bytes long');
        }
        super(buf);
        this.keyType = 'x25519';
        this.publicKey = true;
    }

    /**
     * @return {X25519PublicKey}
     */
    static from() {
        return new X25519PublicKey(Buffer.from(...arguments));
    }

    isX25519Key() {
        return true;
    }

    isPublicKey() {
        return true;
    }
}

module.exports = X25519PublicKey;
