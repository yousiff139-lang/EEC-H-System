import _sodium from 'libsodium-wrappers';

export let sodium: typeof _sodium;

export const initSodium = async () => {
    await _sodium.ready;
    sodium = _sodium;
};

/**
 * Generate Ed25519 Identity Key Pair
 */
export const generateIdentityKeyPair = () => {
    return sodium.crypto_sign_keypair();
};

/**
 * Generate X25519 Messaging Key Pair
 */
export const generateMessagingKeyPair = () => {
    return sodium.crypto_box_keypair();
};

/**
 * Encrypt a Vault (Private Keys) using XChaCha20-Poly1305 with a WrapKey
 */
export const wrapVault = (payload: any, wrapKey: Uint8Array) => {
    const message = JSON.stringify(payload);
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message,
        null, // ad
        null, // nsec
        nonce,
        wrapKey
    );
    return { ciphertext, nonce };
};

/**
 * Decrypt a Vault using wrapKey
 */
export const unwrapVault = (ciphertext: Uint8Array, nonce: Uint8Array, wrapKey: Uint8Array) => {
    const message = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, // nsec
        ciphertext,
        null, // ad
        nonce,
        wrapKey
    );
    return JSON.parse(sodium.to_string(message));
};

/**
 * Wipe a Uint8Array from memory to prevent extraction
 */
export const purgeMemory = (secret: Uint8Array) => {
    sodium.memzero(secret);
};

/**
 * ECDH Shared Secret Derivation
 */
export const deriveSharedSecret = (myPrivateKey: Uint8Array, theirPublicKey: Uint8Array) => {
    return sodium.crypto_scalarmult(myPrivateKey, theirPublicKey);
};

/**
 * Encrypt Message (E2EE)
 */
export const encryptMessage = (plaintext: string, sharedSecret: Uint8Array) => {
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        null,
        null,
        nonce,
        sharedSecret
    );
    return { ciphertext: sodium.to_hex(ciphertext), nonce: sodium.to_hex(nonce) };
};

/**
 * Decrypt Message (E2EE)
 */
export const decryptMessage = (ciphertextHex: string, nonceHex: string, sharedSecret: Uint8Array) => {
    const ciphertext = sodium.from_hex(ciphertextHex);
    const nonce = sodium.from_hex(nonceHex);
    const message = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        null,
        nonce,
        sharedSecret
    );
    return sodium.to_string(message);
};
