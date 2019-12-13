/// <reference types="node" />

// Helper for defining opaque types like crypto_secretstream_xchacha20poly1305_state.
declare const brand: unique symbol;
interface Opaque<T> {
  readonly [brand]: T;
}

// Separate the tag constants that crypto_secretstream_xchacha20poly1305_* functions
// take so that we can use them to limit the input values for those functions.
interface CryptoSecretStreamTagConstants {
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH: 0;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PULL: 1;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY: 2;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL: 3;
}
type CryptoSecretStreamTagValues = CryptoSecretStreamTagConstants[keyof CryptoSecretStreamTagConstants];

interface Constants extends CryptoSecretStreamTagConstants {
  LIBRARY_VERSION_MAJOR: number;
  LIBRARY_VERSION_MINOR: number;
  VERSION_STRING: string;
  BASE64_VARIANT_ORIGINAL: number;
  BASE64_VARIANT_ORIGINAL_NO_PADDING: number;
  BASE64_VARIANT_URLSAFE: number;
  BASE64_VARIANT_URLSAFE_NO_PADDING: number;
  CRYPTO_AEAD_AES256GCM_KEYBYTES: number;
  CRYPTO_AEAD_AES256GCM_NSECBYTES: number;
  CRYPTO_AEAD_AES256GCM_NPUBBYTES: number;
  CRYPTO_AEAD_AES256GCM_ABYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_ABYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES: number;
  CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES: number;
  CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES: number;
  CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES: number;
  CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES: number;
  CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES: number;
  CRYPTO_AUTH_BYTES: number;
  CRYPTO_AUTH_KEYBYTES: number;
  CRYPTO_BOX_SEALBYTES: number;
  CRYPTO_BOX_SECRETKEYBYTES: number;
  CRYPTO_BOX_PUBLICKEYBYTES: number;
  CRYPTO_BOX_KEYPAIRBYTES: number;
  CRYPTO_BOX_MACBYTES: number;
  CRYPTO_BOX_NONCEBYTES: number;
  CRYPTO_BOX_SEEDBYTES: number;
  CRYPTO_KDF_BYTES_MIN: number;
  CRYPTO_KDF_BYTES_MAX: number;
  CRYPTO_KDF_CONTEXTBYTES: number;
  CRYPTO_KDF_KEYBYTES: number;
  CRYPTO_KX_BYTES: number;
  CRYPTO_KX_PRIMITIVE: string;
  CRYPTO_KX_SEEDBYTES: number;
  CRYPTO_KX_KEYPAIRBYTES: number;
  CRYPTO_KX_PUBLICKEYBYTES: number;
  CRYPTO_KX_SECRETKEYBYTES: number;
  CRYPTO_KX_SESSIONKEYBYTES: number;
  CRYPTO_GENERICHASH_BYTES: number;
  CRYPTO_GENERICHASH_BYTES_MIN: number;
  CRYPTO_GENERICHASH_BYTES_MAX: number;
  CRYPTO_GENERICHASH_KEYBYTES: number;
  CRYPTO_GENERICHASH_KEYBYTES_MIN: number;
  CRYPTO_GENERICHASH_KEYBYTES_MAX: number;
  CRYPTO_PWHASH_SALTBYTES: number;
  CRYPTO_PWHASH_STRPREFIX: string;
  CRYPTO_PWHASH_ALG_ARGON2I13: number;
  CRYPTO_PWHASH_ALG_ARGON2ID13: number;
  CRYPTO_PWHASH_ALG_DEFAULT: number;
  CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE: number;
  CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE: number;
  CRYPTO_PWHASH_OPSLIMIT_MODERATE: number;
  CRYPTO_PWHASH_MEMLIMIT_MODERATE: number;
  CRYPTO_PWHASH_OPSLIMIT_SENSITIVE: number;
  CRYPTO_PWHASH_MEMLIMIT_SENSITIVE: number;
  CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES: number;
  CRYPTO_SCALARMULT_BYTES: number;
  CRYPTO_SCALARMULT_SCALARBYTES: number;
  CRYPTO_SHORTHASH_BYTES: number;
  CRYPTO_SHORTHASH_KEYBYTES: number;
  CRYPTO_SECRETBOX_KEYBYTES: number;
  CRYPTO_SECRETBOX_MACBYTES: number;
  CRYPTO_SECRETBOX_NONCEBYTES: number;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES: number;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES: number;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES: number;
  CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX: number;
  CRYPTO_SIGN_BYTES: number;
  CRYPTO_SIGN_SEEDBYTES: number;
  CRYPTO_SIGN_PUBLICKEYBYTES: number;
  CRYPTO_SIGN_SECRETKEYBYTES: number;
  CRYPTO_SIGN_KEYPAIRBYTES: number;
  CRYPTO_STREAM_KEYBYTES: number;
  CRYPTO_STREAM_NONCEBYTES: number;
}

declare namespace Module {
  export type crypto_secretstream_xchacha20poly1305_state = Opaque<
    "crypto_secretstream_xchacha20poly1305_state"
  >;
  export type crypto_generichash_state = Opaque<"crypto_generichash_state">;
  export type Backend = Opaque<"Backend">;

  export class CryptographyKey {
    // Deny types that would otherwise structurally match CryptographyKey.
    // See: https://michalzalecki.com/nominal-typing-in-typescript/
    private readonly __nominal: void;

    constructor(buf: Buffer);
    static from(...args: Parameters<typeof Buffer.from>): CryptographyKey;
    isEd25519Key(): boolean;
    isX25519Key(): boolean;
    isPublicKey(): boolean;
    getLength(): number;
    getBuffer(): Buffer;
    toString(encoding?: string): string;
    slice(): Buffer;
  }
  export class Ed25519PublicKey extends CryptographyKey {
    readonly keyType: "ed25519";
    readonly publicKey: true;
    static from(...args: Parameters<typeof Buffer.from>): Ed25519PublicKey;
  }
  export class Ed25519SecretKey extends CryptographyKey {
    readonly keyType: "ed25519";
    readonly publicKey: false;
    static from(...args: Parameters<typeof Buffer.from>): Ed25519SecretKey;
  }
  export class X25519PublicKey extends CryptographyKey {
    readonly keyType: "x25519";
    readonly publicKey: true;
    static from(...args: Parameters<typeof Buffer.from>): X25519PublicKey;
  }
  export class X25519SecretKey extends CryptographyKey {
    readonly keyType: "x25519";
    readonly publicKey: false;
    static from(...args: Parameters<typeof Buffer.from>): X25519SecretKey;
  }

  export class SodiumError extends Error {}

  export function getBackendObject(
    type?: "SodiumNative" | "LibsodiumWrappers"
  ): Backend;

  // Mix in Constants.* to SodiumPlus instances.
  export interface SodiumPlus extends Constants {}
  export class SodiumPlus {
    readonly backend: Backend;

    constructor(backend: Backend);

    getBackendName(): string;
    isSodiumNative(): boolean;
    isLibsodiumWrappers(): boolean;

    static auto(): Promise<SodiumPlus>;
    ensureLoaded(): Promise<void>;

    crypto_aead_xchacha20poly1305_ietf_decrypt(
      ciphertext: string | Buffer,
      nonce: string | Buffer,
      key: CryptographyKey,
      assocData?: string | Buffer
    ): Promise<Buffer>;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext: string | Buffer,
      nonce: string | Buffer,
      key: CryptographyKey,
      assocData?: string | Buffer
    ): Promise<Buffer>;
    crypto_aead_xchacha20poly1305_ietf_keygen(): Promise<CryptographyKey>;

    crypto_auth(
      message: string | Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_auth_keygen(): Promise<CryptographyKey>;
    crypto_auth_verify(
      message: string | Buffer,
      key: CryptographyKey,
      mac: Buffer
    ): Promise<boolean>;
    crypto_box(
      plaintext: string | Buffer,
      nonce: Buffer,
      myPrivateKey: X25519SecretKey,
      theirPublicKey: X25519PublicKey
    ): Promise<Buffer>;
    crypto_box_open(
      ciphertext: Buffer,
      nonce: Buffer,
      myPrivateKey: X25519SecretKey,
      theirPublicKey: X25519PublicKey
    ): Promise<Buffer>;

    crypto_box_keypair(): Promise<CryptographyKey>;
    crypto_box_keypair_from_secretkey_and_secretkey(
      sKey: X25519SecretKey,
      pKey: X25519PublicKey
    ): Promise<CryptographyKey>;
    crypto_box_secretkey(keypair: CryptographyKey): Promise<X25519SecretKey>;
    crypto_box_publickey(keypair: CryptographyKey): Promise<X25519PublicKey>;
    crypto_box_publickey_from_secretkey(
      secretKey: X25519SecretKey
    ): Promise<X25519PublicKey>;
    crypto_box_seal(
      plaintext: string | Buffer,
      publicKey: X25519PublicKey
    ): Promise<Buffer>;
    crypto_box_seal_open(
      ciphertext: Buffer,
      publicKey: X25519PublicKey,
      secretKey: X25519SecretKey
    ): Promise<Buffer>;

    crypto_generichash(
      message: string | Buffer,
      key?: CryptographyKey | null,
      outputLength?: number
    ): Promise<Buffer>;

    crypto_generichash_init(
      key?: CryptographyKey | null,
      outputLength?: number
    ): Promise<crypto_generichash_state>;
    crypto_generichash_update(
      state: crypto_generichash_state,
      message: string | Buffer
    ): Promise<crypto_generichash_state>;
    crypto_generichash_final(
      state: crypto_generichash_state,
      outputLength?: number
    ): Promise<Buffer>;
    crypto_generichash_keygen(): Promise<CryptographyKey>;

    crypto_kdf_derive_from_key(
      length: number,
      subKeyId: number,
      context: string | Buffer,
      key: CryptographyKey
    ): Promise<CryptographyKey>;
    crypto_kdf_keygen(): Promise<CryptographyKey>;

    crypto_kx_keypair(): Promise<CryptographyKey>;
    crypto_kx_seed_keypair(seed: string | Buffer): Promise<CryptographyKey>;
    crypto_kx_client_session_keys(
      clientPublicKey: X25519PublicKey,
      clientSecretKey: X25519SecretKey,
      serverPublicKey: X25519PublicKey
    ): Promise<CryptographyKey[]>;
    crypto_kx_server_session_keys(
      serverPublicKey: X25519PublicKey,
      serverSecretKey: X25519SecretKey,
      clientPublicKey: X25519PublicKey
    ): Promise<CryptographyKey[]>;

    crypto_onetimeauth(
      message: string | Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_onetimeauth_verify(
      message: string | Buffer,
      key: CryptographyKey,
      tag: Buffer
    ): Promise<boolean>;
    crypto_onetimeauth_keygen(): Promise<CryptographyKey>;

    crypto_pwhash(
      length: number,
      password: string | Buffer,
      salt: Buffer,
      opslimit: number,
      memlimit: number,
      algorithm?: number | null
    ): Promise<CryptographyKey>;
    crypto_pwhash_str(
      password: string | Buffer,
      opslimit: number,
      memlimit: number
    ): Promise<string>;
    crypto_pwhash_str_verify(
      password: string | Buffer,
      hash: string | Buffer
    ): Promise<boolean>;
    crypto_pwhash_str_needs_rehash(
      hash: string | Buffer,
      opslimit: number,
      memlimit: number
    ): Promise<boolean>;

    crypto_scalarmult(
      secretKey: X25519SecretKey,
      publicKey: X25519PublicKey
    ): Promise<CryptographyKey>;
    crypto_scalarmult_base(
      secretKey: X25519SecretKey
    ): Promise<X25519PublicKey>;

    crypto_secretbox(
      plaintext: string | Buffer,
      nonce: Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_secretbox_open(
      ciphertext: Buffer,
      nonce: Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_secretbox_keygen(): Promise<CryptographyKey>;

    crypto_secretstream_xchacha20poly1305_init_push(
      key: CryptographyKey
    ): Promise<crypto_secretstream_xchacha20poly1305_state>;
    crypto_secretstream_xchacha20poly1305_init_pull(
      key: Buffer,
      header: CryptographyKey
    ): Promise<crypto_secretstream_xchacha20poly1305_state>;
    crypto_secretstream_xchacha20poly1305_push(
      state: crypto_secretstream_xchacha20poly1305_state,
      message: string | Buffer,
      ad?: string | Buffer,
      tag?: CryptoSecretStreamTagValues
    ): Promise<Buffer>;
    crypto_secretstream_xchacha20poly1305_pull(
      state: crypto_secretstream_xchacha20poly1305_state,
      ciphertext: Buffer,
      ad?: string | Buffer,
      tag?: CryptoSecretStreamTagValues
    ): Promise<Buffer>;
    crypto_secretstream_xchacha20poly1305_rekey(
      state: crypto_secretstream_xchacha20poly1305_state
    ): Promise<void>;
    crypto_secretstream_xchacha20poly1305_keygen(): Promise<CryptographyKey>;

    crypto_shorthash(
      message: string | Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_shorthash_keygen(): Promise<CryptographyKey>;

    crypto_sign(
      message: string | Buffer,
      secretKey: Ed25519SecretKey
    ): Promise<Buffer>;
    crypto_sign_open(
      message: string | Buffer,
      publicKey: Ed25519PublicKey
    ): Promise<Buffer>;
    crypto_sign_detached(
      message: string | Buffer,
      secretKey: Ed25519SecretKey
    ): Promise<Buffer>;
    crypto_sign_verify_detached(
      message: string | Buffer,
      publicKey: Ed25519PublicKey,
      signature: Buffer
    ): Promise<boolean>;
    crypto_sign_secretkey(keypair: CryptographyKey): Promise<Ed25519SecretKey>;
    crypto_sign_publickey(keypair: CryptographyKey): Promise<Ed25519PublicKey>;
    crypto_sign_seed_keypair(seed: Buffer): Promise<CryptographyKey>;
    crypto_sign_keypair(): Promise<CryptographyKey>;

    crypto_sign_ed25519_sk_to_curve25519(
      sk: Ed25519SecretKey
    ): Promise<X25519SecretKey>;

    crypto_sign_ed25519_pk_to_curve25519(
      pk: Ed25519PublicKey
    ): Promise<X25519PublicKey>;

    crypto_stream(
      length: number,
      nonce: Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_stream_xor(
      plaintext: string | Buffer,
      nonce: Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    crypto_stream_keygen(): Promise<CryptographyKey>;

    randombytes_buf(num: number): Promise<Buffer>;
    randombytes_uniform(upperBound: number): Promise<number>;
    sodium_add(val: Buffer, addv: Buffer): Promise<Buffer>;
    sodium_bin2hex(encoded: Buffer): Promise<string>;
    sodium_compare(b1: Buffer, b2: Buffer): Promise<number>;
    sodium_hex2bin(encoded: Buffer|string): Promise<Buffer>;
    sodium_increment(buf: Buffer): Promise<Buffer>;
    sodium_is_zero(buf: Buffer, len: number): Promise<Buffer>;
    sodium_memcmp(b1: Buffer, b2: Buffer): Promise<boolean>;
    sodium_memzero(buf: Buffer): Promise<void>;
    sodium_pad(buf: string | Buffer, blockSize: number): Promise<Buffer>;
    sodium_unpad(buf: string | Buffer, blockSize: number): Promise<Buffer>;
  }

  export class SodiumUtil {
    static cloneBuffer(buf: Buffer): Promise<Buffer>;
    static populateConstants<T>(anyobject: T): T & Constants;
    static toBuffer(
      stringOrBuffer: string | Buffer | Uint8Array | Promise<Buffer>
    ): Promise<Buffer>;
  }

  export class SodiumPolyfill {
    static crypto_onetimeauth(
      message: string | Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    static crypto_onetimeauth_verify(
      message: string | Buffer,
      key: CryptographyKey,
      tag: Buffer
    ): Promise<boolean>;
    static crypto_stream_xor(
      plaintext: string | Buffer,
      nonce: Buffer,
      key: CryptographyKey
    ): Promise<Buffer>;
    static crypto_pwhash_str_needs_rehash(
      hash: string | Buffer,
      opslimit: number,
      memlimit: number
    ): Promise<boolean>;
  }
}

export = Module;
