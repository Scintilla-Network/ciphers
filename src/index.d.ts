/**
 * Cipher function interface
 */
export interface CipherFunction {
  /**
   * Encrypt data with automatic nonce handling
   * @param data - Data to encrypt
   * @param key - Encryption key (16, 24, or 32 bytes for AES; 32 bytes for ChaCha20)
   * @param nonce - Optional nonce (if not provided, random nonce will be generated)
   * @returns Encrypted data with nonce prepended
   */
  encrypt(data: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Uint8Array;

  /**
   * Decrypt data with automatic nonce extraction
   * @param encryptedData - Encrypted data with nonce prepended (from encrypt function)
   * @param key - Decryption key
   * @param nonce - Optional explicit nonce (if provided, encryptedData is treated as pure ciphertext)
   * @returns Decrypted plaintext data
   */
  decrypt(encryptedData: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Uint8Array;
}

/**
 * Utility functions
 */
export interface Utils {
  /**
   * Generate cryptographically secure random bytes
   * @param length - Number of bytes to generate
   * @returns Random bytes
   */
  randomBytes(length: number): Uint8Array;

  /**
   * Convert bytes to hexadecimal string
   * @param bytes - Bytes to convert
   * @returns Hexadecimal string
   */
  bytesToHex(bytes: Uint8Array): string;

  /**
   * Convert hexadecimal string to bytes
   * @param hex - Hexadecimal string to convert
   * @returns Bytes
   */
  hexToBytes(hex: string): Uint8Array;
}

/**
 * AES-GCM cipher (industry standard, 12-byte nonces)
 * Supports 128, 192, and 256-bit keys
 */
export const aesgcm: CipherFunction;

/**
 * ChaCha20-Poly1305 cipher (TLS 1.3 standard, 12-byte nonces)
 * Requires 256-bit keys
 */
export const chacha20: CipherFunction;

/**
 * XChaCha20-Poly1305 cipher (extended nonce variant, 24-byte nonces)
 * Requires 256-bit keys, safe with random nonces
 */
export const xchacha20: CipherFunction;

/**
 * Utility functions for key generation and data conversion
 */
export const utils: Utils; 