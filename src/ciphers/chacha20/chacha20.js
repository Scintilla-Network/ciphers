import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '../../utils/index.js';

export const chacha20 = {
    /**
     * Encrypt data with ChaCha20-Poly1305 (TLS 1.3 standard)
     * @param {Uint8Array} data - Data to encrypt
     * @param {Uint8Array} key - Encryption key (32 bytes)
     * @param {Uint8Array} [nonce] - Optional nonce (12 bytes). If not provided, a random nonce will be generated
     * @returns {Uint8Array} - Encrypted data with nonce prepended (nonce + ciphertext + tag)
     */
    encrypt: (data, key, nonce = randomBytes(12)) => {
        const encrypted = chacha20poly1305(key, nonce).encrypt(data);
        // Prepend nonce to encrypted data
        const result = new Uint8Array(nonce.length + encrypted.length);
        result.set(nonce, 0);
        result.set(encrypted, nonce.length);
        return result;
    },

    /**
     * Decrypt data with ChaCha20-Poly1305 (TLS 1.3 standard)
     * @param {Uint8Array} encryptedData - Encrypted data with nonce prepended (from encrypt function)
     * @param {Uint8Array} key - Decryption key (32 bytes)
     * @param {Uint8Array} [nonce] - Optional explicit nonce. If not provided, nonce will be extracted from encryptedData
     * @returns {Uint8Array} - Decrypted plaintext data
     */
    decrypt: (encryptedData, key,  nonce = undefined) => {
        let ciphertext;
        
        if (nonce === undefined) {
            // Extract nonce from the beginning of encryptedData (first 12 bytes)
            nonce = encryptedData.slice(0, 12);
            ciphertext = encryptedData.slice(12);
        } else {
            // Use provided nonce and treat encryptedData as pure ciphertext
            ciphertext = encryptedData;
        }
        
        return chacha20poly1305(key, nonce).decrypt(ciphertext);
    }
};
