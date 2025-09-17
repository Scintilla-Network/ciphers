import { bytesToHex, hexToBytes, randomBytes } from '@noble/ciphers/utils.js';

/**
 * Utils
 * @namespace utils
 */
export const utils = {
    bytesToHex,
    hexToBytes,
    randomBytes
}

// Re-export for convenience
export {
    bytesToHex,
    hexToBytes,
    randomBytes
}

export default utils;