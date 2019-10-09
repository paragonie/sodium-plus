const crypto = require('crypto');
const Util = require('./util');

module.exports = class SodiumPolyfill {
    /**
     * @param {string|Buffer} hash
     * @param {number} opslimit
     * @param {number} memlimit
     * @return {Promise<boolean>}
     */
    static async crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit) {
        let pwhash = (await Util.toBuffer(hash)).toString('utf-8');
        let pieces = pwhash.split('$');
        let expect = 'm=' + (memlimit >> 10) + ',t=' + opslimit + ',p=1';
        if (expect.length !== pieces[3].length) {
            return true;
        }
        return !crypto.timingSafeEqual(
            await Util.toBuffer(expect),
            await Util.toBuffer(pieces[3])
        );
    }
};
