import { randomBytes, bytesToHex, hexToBytes } from '@noble/ciphers/utils.js';

/**
 * Utility functions for cryptographic operations
 */
export interface Utils {
  /**
   * Generate cryptographically secure random bytes
   * @param length - Number of bytes to generate
   * @returns Random bytes
   */
  randomBytes: typeof randomBytes;

  /**
   * Convert bytes to hexadecimal string
   * @param bytes - Bytes to convert
   * @returns Hexadecimal string
   */
  bytesToHex: typeof bytesToHex;

  /**
   * Convert hexadecimal string to bytes
   * @param hex - Hexadecimal string to convert
   * @returns Bytes
   */
  hexToBytes: typeof hexToBytes;
}

/**
 * Utility functions for cryptographic operations
 */
export const utils: Utils;

// Re-export for convenience
export const randomBytes: typeof import('@noble/ciphers/utils.js').randomBytes;
export const bytesToHex: typeof import('@noble/ciphers/utils.js').bytesToHex;
export const hexToBytes: typeof import('@noble/ciphers/utils.js').hexToBytes;

export default utils; 