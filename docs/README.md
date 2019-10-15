# Table of Contents

* [Table of Contents](#table-of-contents) (you are here)
* [Getting Started](getting-started.md#getting-started)
  * [CryptographyKey](getting-started.md#cryptographykey)
* [SodiumPlus Methods](SodiumPlus)
  * [AEAD (XChaCha20-Poly1305)](SodiumPlus/AEAD.md#aead)
    * [crypto_aead_xchacha20poly1305_ietf_decrypt](SodiumPlus/AEAD.md#crypto_aead_xchacha20poly1305_ietf_decrypt)
    * [crypto_aead_xchacha20poly1305_ietf_encrypt](SodiumPlus/AEAD.md#crypto_aead_xchacha20poly1305_ietf_encrypt)
    * [crypto_aead_xchacha20poly1305_ietf_keygen](SodiumPlus/AEAD.md#crypto_aead_xchacha20poly1305_ietf_keygen)
    * [Example for crypto_aead_xchacha20poly1305_ietf_*](SodiumPlus/AEAD.md#example-for-crypto_aead_xchacha20poly1305_ietf_)
  * [Shared-key authentication](SodiumPlus/shared-key-authentication.md)
    * [crypto_auth](SodiumPlus/shared-key-authentication.md#crypto_auth)
    * [crypto_auth_verify](SodiumPlus/shared-key-authentication.md#crypto_auth_verify)
    * [crypto_auth_keygen](SodiumPlus/shared-key-authentication.md#crypto_auth_keygen)
    * [Example for crypto_auth](SodiumPlus/shared-key-authentication.md#example-for-crypto_auth)
  * [Authenticated public-key encryption](SodiumPlus/authenticated-public-key-encryption.md)
    * [crypto_box](SodiumPlus/authenticated-public-key-encryption.md#crypto_box)
    * [crypto_box_open](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_open)
    * [crypto_box_keypair](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_keypair)
    * [crypto_box_keypair_from_secretkey_and_secretkey](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_keypair_from_secretkey_and_secretkey)
    * [crypto_box_publickey](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_publickey)
    * [crypto_box_secretkey](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_secretkey)
    * [crypto_box_publickey_from_secretkey](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_publickey_from_secretkey)
    * [Example for crypto_box](SodiumPlus/authenticated-public-key-encryption.md#example-for-crypto_box)
  * [Sealed boxes (anonymous public-key encryption)](SodiumPlus/sealed-boxes.md)
    * [crypto_box_seal](SodiumPlus/sealed-boxes.md#crypto_box_seal)
    * [crypto_box_seal_open](SodiumPlus/sealed-boxes.md#crypto_box_seal_open)
    * [Example for crypto_box_seal](SodiumPlus/sealed-boxes.md#example-for-crypto_box_seal)
  * [General-purpose cryptographic hash](SodiumPlus/general-purpose-cryptographic-hash.md)
    * [crypto_generichash](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash)
    * [crypto_generichash_init](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_init)
    * [crypto_generichash_update](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_update)
    * [crypto_generichash_final](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_final)
    * [crypto_generichash_keygen](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_keygen)
    * [Example for crypto_generichash](SodiumPlus/general-purpose-cryptographic-hash.md#example-for-crypto_generichash)
  * [Key derivation](SodiumPlus/key-derivation.md)
    * [crypto_kdf_derive_from_key](SodiumPlus/key-derivation.md#crypto_kdf_derive_from_key)
    * [crypto_kdf_keygen](SodiumPlus/key-derivation.md#crypto_kdf_keygen)
    * [Example for crypto_kdf](SodiumPlus/key-derivation.md#example-for-crypto_kdf)
  * [Key exchange](SodiumPlus/key-exchange.md)
    * [crypto_kx_keypair](SodiumPlus/key-exchange.md#crypto_kx_keypair)
    * [crypto_kx_seed_keypair](SodiumPlus/key-exchange.md#crypto_kx_seed_keypair)
    * [crypto_kx_client_session_keys](SodiumPlus/key-exchange.md#crypto_kx_client_session_keys)
    * [crypto_kx_server_session_keys](SodiumPlus/key-exchange.md#crypto_kx_server_session_keys)
    * [Example for crypto_kx](SodiumPlus/key-exchange.md#example-for-crypto_kx)
  * [Password-based key derivation](SodiumPlus/password-based-key-derivation.md)
    * [crypto_pwhash](SodiumPlus/password-based-key-derivation.md#crypto_pwhash)
    * [Example for crypto_pwhash](SodiumPlus/password-based-key-derivation.md#example-for-crypto_pwhash)
  * [Password hashing and storage](SodiumPlus/password-hashing-and-storage.md)
    * [crypto_pwhash_str](SodiumPlus/password-hashing-and-storage.md#crypto_pwhash_str)
    * [crypto_pwhash_str_needs_rehash](SodiumPlus/password-hashing-and-storage.md#crypto_pwhash_str_needs_rehash)
    * [crypto_pwhash_str_verify](SodiumPlus/password-hashing-and-storage.md#crypto_pwhash_str_verify)
    * [Example for crypto_pwhash_str](SodiumPlus/password-hashing-and-storage.md#example-for-crypto_pwhash_str)
  * [Scalar multiplication over Curve25519 (advanced)](SodiumPlus/scalar-multiplication.md)
    * [crypto_scalarmult](SodiumPlus/scalar-multiplication.md#crypto_scalarmult)
    * [crypto_scalarmult_base](SodiumPlus/scalar-multiplication.md#crypto_scalarmult_base)
    * [Example for crypto_scalarmult](SodiumPlus/scalar-multiplication.md#example-for-crypto_scalarmult)
  * [Shared-key authenticated encryption](SodiumPlus/shared-key-authenticated-encryption.md)
    * [crypto_secretbox](SodiumPlus/shared-key-authenticated-encryption.md#crypto_secretbox)
    * [crypto_secretbox_open](SodiumPlus/shared-key-authenticated-encryption.md#crypto_secretbox_open)
    * [crypto_secretbox_keygen](SodiumPlus/shared-key-authenticated-encryption.md#crypto_secretbox_keygen)
    * [Example for crypto_secretbox](SodiumPlus/shared-key-authenticated-encryption.md#example-for-crypto_secretbox)
  * [Short-input hashing](SodiumPlus/short-input-hashing.md)
    * [crypto_shorthash](SodiumPlus/short-input-hashing.md#crypto_shorthash)
    * [crypto_shorthash_keygen](SodiumPlus/short-input-hashing.md#crypto_shorthash_keygen)
    * [Example for crypto_shorthash](SodiumPlus/short-input-hashing.md#example-for-crypto_shorthash)
  * [Digital signatures](SodiumPlus/digital-signatures.md)
    * [crypto_sign](SodiumPlus/digital-signatures.md#crypto_sign)
    * [crypto_sign_open](SodiumPlus/digital-signatures.md#crypto_sign_open)
    * [crypto_sign_detached](SodiumPlus/digital-signatures.md#crypto_sign_detached)
    * [crypto_sign_verify_detached](SodiumPlus/digital-signatures.md#crypto_sign_verify_detached)
    * [crypto_sign_keypair](SodiumPlus/digital-signatures.md#crypto_sign_keypair)
    * [crypto_sign_publickey](SodiumPlus/digital-signatures.md#crypto_sign_publickey)
    * [crypto_sign_secretkey](SodiumPlus/digital-signatures.md#crypto_sign_secretkey)
    * [crypto_sign_ed25519_sk_to_curve25519](SodiumPlus/digital-signatures.md#crypto_sign_ed25519_sk_to_curve25519)
    * [crypto_sign_ed25519_pk_to_curve25519](SodiumPlus/digital-signatures.md#crypto_sign_ed25519_pk_to_curve25519)
    * [Example for crypto_sign](SodiumPlus/digital-signatures.md#example-for-crypto_sign)
  * [Randomness](SodiumPlus/randomness.md)
    * [randombytes_buf](SodiumPlus/randomness.md#randombytes_buf)
    * [randombytes_uniform](SodiumPlus/randomness.md#randombytes_uniform)
    * [Example for randombytes](SodiumPlus/randomness.md#example-for-randombytes)

# Getting Started

> [Moved](getting-started.md)

## CryptographyKey

> [Moved](getting-started.md#cryptographykey)

# SodiumPlus Methods

## AEAD

> [Moved](SodiumPlus/AEAD.md#aead)

### crypto_aead_xchacha20poly1305_ietf_decrypt

> [Moved](SodiumPlus/AEAD.md#crypto_aead_xchacha20poly1305_ietf_decrypt)

### crypto_aead_xchacha20poly1305_ietf_encrypt

> [Moved](SodiumPlus/AEAD.md#crypto_aead_xchacha20poly1305_ietf_encrypt)

### crypto_aead_xchacha20poly1305_ietf_keygen

> [Moved](SodiumPlus/AEAD.md#crypto_aead_xchacha20poly1305_ietf_keygen)

### Example for crypto_aead_xchacha20poly1305_ietf_*

> [Moved](SodiumPlus/AEAD.md#example-for-crypto_aead_xchacha20poly1305_ietf_)

## Shared-key authentication

> [Moved](SodiumPlus/shared-key-authentication.md)

### crypto_auth

> [Moved](SodiumPlus/shared-key-authentication.md#crypto_auth)

### crypto_auth_verify

> [Moved](SodiumPlus/shared-key-authentication.md#crypto_auth_verify)

### crypto_auth_keygen

> [Moved](SodiumPlus/shared-key-authentication.md#crypto_auth_keygen)

### Example for crypto_auth

> [Moved](SodiumPlus/shared-key-authentication.md#example-for-crypto_auth)

## Authenticated public-key encryption

> [Moved](SodiumPlus/authenticated-public-key-encryption.md)

### crypto_box

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box)

### crypto_box_open

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_open)

### crypto_box_keypair

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_keypair)

### crypto_box_keypair_from_secretkey_and_secretkey

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_keypair_from_secretkey_and_secretkey)

### crypto_box_publickey

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_publickey)

### crypto_box_secretkey

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_secretkey)

### crypto_box_publickey_from_secretkey

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#crypto_box_publickey_from_secretkey)

### Example for crypto_box

> [Moved](SodiumPlus/authenticated-public-key-encryption.md#example-for-crypto_box)

## Sealed boxes

> [Moved](SodiumPlus/sealed-boxes.md)

### crypto_box_seal

> [Moved](SodiumPlus/sealed-boxes.md#crypto_box_seal)

### crypto_box_seal_open

> [Moved](SodiumPlus/sealed-boxes.md#crypto_box_seal_open)

### Example for crypto_box_seal

> [Moved](SodiumPlus/sealed-boxes.md#example-for-crypto_box_seal)

## General-purpose cryptographic hash

> [Moved](SodiumPlus/general-purpose-cryptographic-hash.md)

### crypto_generichash

### crypto_generichash_keygen

> [Moved](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_keygen)

### crypto_generichash_init

> [Moved](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_init)

### crypto_generichash_update

> [Moved](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_update)

### crypto_generichash_final

> [Moved](SodiumPlus/general-purpose-cryptographic-hash.md#crypto_generichash_final)

### Example for crypto_generichash

> [Moved](SodiumPlus/general-purpose-cryptographic-hash.md#example-for-crypto_generichash)

## Key derivation

> [Moved](SodiumPlus/key-derivation.md)

### crypto_kdf_derive_from_key

> [Moved](SodiumPlus/key-derivation.md#crypto_kdf_derive_from_key)

### crypto_kdf_keygen

> [Moved](SodiumPlus/key-derivation.md#crypto_kdf_keygen)

### Example for crypto_kdf

> [Moved](SodiumPlus/key-derivation.md#example-for-crypto_kdf)

## Key exchange

> [Moved](SodiumPlus/key-exchange.md)

### crypto_kx_keypair

> [Moved](SodiumPlus/key-exchange.md#crypto_kx_keypair)

### crypto_kx_seed_keypair

> [Moved](SodiumPlus/key-exchange.md#crypto_kx_seed_keypair)

### crypto_kx_client_session_keys

> [Moved](SodiumPlus/key-exchange.md#crypto_kx_client_session_keys)

### crypto_kx_server_session_keys

> [Moved](SodiumPlus/key-exchange.md#crypto_kx_server_session_keys)

### Example for crypto_kx

> [Moved](SodiumPlus/key-exchange.md#example-for-crypto_kx)

## Password-based key derivation

> [Moved](SodiumPlus/password-based-key-derivation.md)

### crypto_pwhash

> [Moved](SodiumPlus/password-based-key-derivation.md#crypto_pwhash)

### Example for crypto_pwhash

> [Moved](SodiumPlus/password-based-key-derivation.md#example-for-crypto_pwhash)

## Password hashing and storage

> [Moved](SodiumPlus/password-hashing-and-storage.md)

### crypto_pwhash_str

> [Moved](SodiumPlus/password-hashing-and-storage.md#crypto_pwhash_str)

### crypto_pwhash_str_needs_rehash

> [Moved](SodiumPlus/password-hashing-and-storage.md#crypto_pwhash_str_needs_rehash)

### crypto_pwhash_str_verify

> [Moved](SodiumPlus/password-hashing-and-storage.md#crypto_pwhash_str_verify)

### Example for crypto_pwhash_str

> [Moved](SodiumPlus/password-hashing-and-storage.md#example-for-crypto_pwhash_str)

## Scalar multiplication over Curve25519

> [Moved](SodiumPlus/scalar-multiplication.md)

### crypto_scalarmult

> [Moved](SodiumPlus/scalar-multiplication.md#crypto_scalarmult)

### crypto_scalarmult_base

> [Moved](SodiumPlus/scalar-multiplication.md#crypto_scalarmult_base)

### Example for crypto_scalarmult

> [Moved](SodiumPlus/scalar-multiplication.md#example-for-crypto_scalarmult)

## Shared-key authenticated encryption

> [Moved](SodiumPlus/shared-key-authenticated-encryption.md)

### crypto_secretbox

> [Moved](SodiumPlus/shared-key-authenticated-encryption.md#crypto_secretbox)

### crypto_secretbox_open

> [Moved](SodiumPlus/shared-key-authenticated-encryption.md#crypto_secretbox_open)

### crypto_secretbox_keygen

> [Moved](SodiumPlus/shared-key-authenticated-encryption.md#crypto_secretbox_keygen)

### Example for crypto_secretbox

> [Moved](SodiumPlus/shared-key-authenticated-encryption.md#example-for-crypto_secretbox)

## Short-input hashing

> [Moved](SodiumPlus/short-input-hashing.md)

### crypto_shorthash

> [Moved](SodiumPlus/short-input-hashing.md#crypto_shorthash)

### crypto_shorthash_keygen

> [Moved](SodiumPlus/short-input-hashing.md#crypto_shorthash_keygen)

### Example for crypto_shorthash

> [Moved](SodiumPlus/short-input-hashing.md#example-for-crypto_shorthash)

## Digital signatures

> [Moved](SodiumPlus/digital-signatures.md)

### crypto_sign

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign)

### crypto_sign_open

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_open)

### crypto_sign_detached

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_detached)

### crypto_sign_verify_detached

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_verify_detached)

### crypto_sign_keypair

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_keypair)

### crypto_sign_publickey

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_publickey)

### crypto_sign_secretkey

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_secretkey)

### crypto_sign_ed25519_sk_to_curve25519

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_ed25519_sk_to_curve25519)

### crypto_sign_ed25519_pk_to_curve25519

> [Moved](SodiumPlus/digital-signatures.md#crypto_sign_ed25519_pk_to_curve25519)

### Example for crypto_sign

> [Moved](SodiumPlus/digital-signatures.md#example-for-crypto_sign)

## Randomness

> [Moved](SodiumPlus/randomness.md)

### randombytes_buf

> [Moved](SodiumPlus/randomness.md#randombytes_buf)

### randombytes_uniform

> [Moved](SodiumPlus/randomness.md#randombytes_uniform)

### Example for randombytes

> [Moved](SodiumPlus/randomness.md#example-for-randombytes)
