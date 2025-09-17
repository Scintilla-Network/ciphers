/**
 * ChaCha20-Poly1305 cipher implementation
 */
export interface ChaCha20Cipher {
  /**
   * Encrypt data with ChaCha20-Poly1305 (TLS 1.3 standard)
   * @param key - Encryption key (32 bytes)
   * @param data - Data to encrypt
   * @param nonce - Optional nonce (12 bytes). If not provided, a random nonce will be generated
   * @returns Encrypted data with nonce prepended (nonce + ciphertext + tag)
   */
  encrypt(key: Uint8Array, data: Uint8Array, nonce?: Uint8Array): Uint8Array;

  /**
   * Decrypt data with ChaCha20-Poly1305 (TLS 1.3 standard)
   * @param key - Decryption key (32 bytes)
   * @param encryptedData - Encrypted data with nonce prepended (from encrypt function)
   * @param nonce - Optional explicit nonce. If not provided, nonce will be extracted from encryptedData
   * @returns Decrypted plaintext data
   */
  decrypt(key: Uint8Array, encryptedData: Uint8Array, nonce?: Uint8Array): Uint8Array;
}

/**
 * ChaCha20-Poly1305 cipher (TLS 1.3 standard, 12-byte nonces)
 * Requires 256-bit keys
 */
export const chacha20: ChaCha20Cipher;
