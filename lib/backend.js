const CryptographyKey = require('./cryptography-key');
/* istanbul ignore if */
if (typeof (Buffer) === 'undefined') {
    let Buffer = require('buffer/').Buffer;
}

module.exports = class Backend {
    constructor() {
        // NOP
        this.backendName = 'UndefinedBackend';
    }

    /**
     * @param {CryptographyKey} sKey
     * @param {CryptographyKey} pKey
     * @return {Promise<CryptographyKey>}
     */
    async crypto_box_keypair_from_secretkey_and_publickey(sKey, pKey) {
        /* istanbul ignore if */
        if (sKey.getLength() !== 32) {
            throw new Error('Secret key must be 32 bytes');
        }
        /* istanbul ignore if */
        if (pKey.getLength() !== 32) {
            throw new Error('Public key must be 32 bytes');
        }
        const keypair = Buffer.alloc(64);
        sKey.getBuffer().copy(keypair, 0, 0, 32);
        pKey.getBuffer().copy(keypair, 32, 0, 32);
        return new CryptographyKey(Buffer.from(keypair));
    }
};
