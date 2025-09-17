/**
 * AES-GCM cipher implementation
 */
export interface AESGCMCipher {
  /**
   * Encrypt data with AES-GCM
   * @param data - Data to encrypt
   * @param key - Encryption key (16, 24, or 32 bytes for AES-128/192/256)
   * @param nonce - Optional nonce (12 bytes). If not provided, a random nonce will be generated
   * @returns Encrypted data with nonce prepended (nonce + ciphertext + tag)
   */
  encrypt(data: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Uint8Array;

  /**
   * Decrypt data with AES-GCM
   * @param encryptedData - Encrypted data with nonce prepended (from encrypt function)
   * @param key - Decryption key (16, 24, or 32 bytes)
   * @param nonce - Optional explicit nonce. If not provided, nonce will be extracted from encryptedData
   * @returns Decrypted plaintext data
   */
  decrypt(encryptedData: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Uint8Array;
}

/**
 * AES-GCM cipher (industry standard, 12-byte nonces)
 * Supports 128, 192, and 256-bit keys
 */
export const aesgcm: AESGCMCipher;
