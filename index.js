module.exports = {
    /**
     * This is only meant to be used for advanced users.
     *
     * A backend object can be passed to the SodiumPlus constructor.
     *
     * @param {string} type
     * @return {Backend}
     * @throws {SodiumError}
     * @throws {Error}
     */
    getBackendObject: (type = '') => {
        if (type === 'SodiumNative') {
            // This one may error out. You should catch it in your code.
            // We won't here. Use the `await SodiumPlus.auto()` API instead!
            return require('./lib/backend/sodiumnative');
        } else if (type === 'LibsodiumWrappers') {
            return require('./lib/backend/libsodium-wrappers');
        } else if (type.length === 0) {
            return require('./lib/backend');
        }

        // Default: Throw a SodiumError
        let SodiumError = require('./lib/sodium-error');
        throw new SodiumError(`Unrecognized backend type: ${type}`);
    },
    CryptographyKey: require('./lib/cryptography-key'),
    Ed25519PublicKey: require('./lib/keytypes/ed25519pk'),
    Ed25519SecretKey: require('./lib/keytypes/ed25519sk'),
    SodiumError: require('./lib/sodium-error'),
    SodiumPlus: require('./lib/sodiumplus'),
    SodiumPolyfill: require('./lib/polyfill'),
    SodiumUtil: require('./lib/util'),
    X25519PublicKey: require('./lib/keytypes/x25519pk'),
    X25519SecretKey: require('./lib/keytypes/x25519sk')
};
