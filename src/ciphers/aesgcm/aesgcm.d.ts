/**
 * AES-GCM cipher implementation
 */
export interface AESGCMCipher {
  /**
   * Encrypt data with AES-GCM
   * @param key - Encryption key (16, 24, or 32 bytes for AES-128/192/256)
   * @param data - Data to encrypt
   * @param nonce - Optional nonce (12 bytes). If not provided, a random nonce will be generated
   * @returns Encrypted data with nonce prepended (nonce + ciphertext + tag)
   */
  encrypt(key: Uint8Array, data: Uint8Array, nonce?: Uint8Array): Uint8Array;

  /**
   * Decrypt data with AES-GCM
   * @param key - Decryption key (16, 24, or 32 bytes)
   * @param encryptedData - Encrypted data with nonce prepended (from encrypt function)
   * @param nonce - Optional explicit nonce. If not provided, nonce will be extracted from encryptedData
   * @returns Decrypted plaintext data
   */
  decrypt(key: Uint8Array, encryptedData: Uint8Array, nonce?: Uint8Array): Uint8Array;
}

/**
 * AES-GCM cipher (industry standard, 12-byte nonces)
 * Supports 128, 192, and 256-bit keys
 */
export const aesgcm: AESGCMCipher;
