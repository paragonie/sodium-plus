const {
    CryptographyKey,
    Ed25519PublicKey,
    Ed25519SecretKey,
    SodiumError,
    SodiumPlus,
    SodiumPolyfill,
    SodiumUtil,
    X25519PublicKey,
    X25519SecretKey
} = require('./index');

// Load dependencies into window
(async function(){
    window.CryptographyKey = CryptographyKey;
    window.Ed25519PublicKey = Ed25519PublicKey;
    window.Ed25519SecretKey = Ed25519SecretKey;
    window.SodiumError = SodiumError;
    window.SodiumPlus = SodiumPlus;
    window.SodiumPolyfill = SodiumPolyfill;
    window.SodiumUtil = SodiumUtil;
    window.X25519PublicKey = X25519PublicKey;
    window.X25519SecretKey = X25519SecretKey;
    window.sodium = await SodiumPlus.auto();
})();
