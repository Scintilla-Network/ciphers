/**
 * XChaCha20-Poly1305 cipher implementation
 */
export interface XChaCha20Cipher {
  /**
   * Encrypt data with XChaCha20-Poly1305 (extended nonce variant)
   * @param data - Data to encrypt
   * @param key - Encryption key (32 bytes)
   * @param nonce - Optional nonce (24 bytes). If not provided, a random nonce will be generated
   * @returns Encrypted data with nonce prepended (nonce + ciphertext + tag)
   */
  encrypt(data: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Uint8Array;

  /**
   * Decrypt data with XChaCha20-Poly1305 (extended nonce variant)
   * @param encryptedData - Encrypted data with nonce prepended (from encrypt function)
   * @param key - Decryption key (32 bytes)
   * @param nonce - Optional explicit nonce. If not provided, nonce will be extracted from encryptedData
   * @returns Decrypted plaintext data
   */
  decrypt(encryptedData: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Uint8Array;
}

/**
 * XChaCha20-Poly1305 cipher (extended nonce variant, 24-byte nonces)
 * Requires 256-bit keys, safe with random nonces
 */
export const xchacha20: XChaCha20Cipher;
