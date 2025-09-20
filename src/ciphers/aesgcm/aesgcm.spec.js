import { describe, it, expect } from '@scintilla-network/litest';
import { aesgcm } from './aesgcm.js';
import { randomBytes } from '../../utils/index.js';

describe('AES-GCM', () => {
  const key = new Uint8Array(32).fill(1); // Deterministic key for testing
  const message = new TextEncoder().encode('Hello, AES-GCM!');

  describe('Basic encrypt/decrypt', () => {
    it('should encrypt and decrypt successfully with auto-generated nonce', () => {
      const encrypted = aesgcm.encrypt(message, key);
      const decrypted = aesgcm.decrypt(encrypted, key);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, AES-GCM!');
    });

    it('should encrypt and decrypt with custom nonce', () => {
      const customNonce = new Uint8Array(12).fill(42); // 12-byte nonce for AES-GCM
      const encrypted = aesgcm.encrypt(message, key, customNonce);
      const decrypted = aesgcm.decrypt(encrypted, key);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, AES-GCM!');
    });

    it('should decrypt with explicit nonce parameter', () => {
      const customNonce = new Uint8Array(12).fill(99);
      const encrypted = aesgcm.encrypt(message, key, customNonce);
      
      // Extract ciphertext without nonce
      const ciphertext = encrypted.slice(12);
      const decrypted = aesgcm.decrypt(ciphertext, key, customNonce);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, AES-GCM!');
    });
  });

  describe('Nonce handling', () => {
    it('should prepend nonce to encrypted data', () => {
      const customNonce = new Uint8Array(12).fill(123);
      const encrypted = aesgcm.encrypt(message, key, customNonce);
      
      // First 12 bytes should be the nonce
      const extractedNonce = encrypted.slice(0, 12);
      expect(extractedNonce).toEqual(customNonce);
    });

    it('should generate different nonces for each encryption', () => {
      const encrypted1 = aesgcm.encrypt(message, key);
      const encrypted2 = aesgcm.encrypt(message, key);
      
      const nonce1 = encrypted1.slice(0, 12);
      const nonce2 = encrypted2.slice(0, 12);
      
      expect(nonce1).not.toEqual(nonce2);
    });

    it('should use 12-byte nonces (industry standard)', () => {
      const encrypted = aesgcm.encrypt(message, key);
      
      // AES-GCM uses 12-byte nonces
      expect(encrypted.length).toBeGreaterThanOrEqual(12 + message.length + 16); // nonce + message + tag
    });
  });

  describe('Key size support', () => {
    it('should work with 128-bit keys', () => {
      const key128 = new Uint8Array(16).fill(1);
      const encrypted = aesgcm.encrypt(message, key128);
      const decrypted = aesgcm.decrypt(encrypted, key128);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, AES-GCM!');
    });

    it('should work with 192-bit keys', () => {
      const key192 = new Uint8Array(24).fill(1);
      const encrypted = aesgcm.encrypt(message, key192);
      const decrypted = aesgcm.decrypt(encrypted, key192);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, AES-GCM!');
    });

    it('should work with 256-bit keys', () => {
      const key256 = new Uint8Array(32).fill(1);
      const encrypted = aesgcm.encrypt(message, key256);
      const decrypted = aesgcm.decrypt(encrypted, key256);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, AES-GCM!');
    });
  });

  describe('Data integrity', () => {
    it('should handle empty messages', () => {
      const emptyMessage = new Uint8Array(0);
      const encrypted = aesgcm.encrypt(emptyMessage, key);
      const decrypted = aesgcm.decrypt(encrypted, key);
      
      expect(decrypted).toEqual(emptyMessage);
    });

    it('should handle large messages', () => {
      const largeMessage = new Uint8Array(10000).fill(255);
      const encrypted = aesgcm.encrypt(largeMessage, key);
      const decrypted = aesgcm.decrypt(encrypted, key);
      
      expect(decrypted).toEqual(largeMessage);
    });

    it('should produce different ciphertexts for same message with different nonces', () => {
      const nonce1 = new Uint8Array(12).fill(1);
      const nonce2 = new Uint8Array(12).fill(2);
      
      const encrypted1 = aesgcm.encrypt(message, key, nonce1);
      const encrypted2 = aesgcm.encrypt(message, key, nonce2);
      
      expect(encrypted1).not.toEqual(encrypted2);
    });
  });

  describe('Error handling', () => {
    it('should fail with wrong key', () => {
      const wrongKey = new Uint8Array(32).fill(2);
      const encrypted = aesgcm.encrypt(message, key);
      
      expect(() => {
        aesgcm.decrypt(encrypted, wrongKey);
      }).toThrow();
    });

    it('should fail with corrupted ciphertext', () => {
      const encrypted = aesgcm.encrypt(message, key);
      encrypted[encrypted.length - 1] ^= 1; // Flip a bit in the tag
      
      expect(() => {
        aesgcm.decrypt(encrypted, key);
      }).toThrow();
    });

    it('should fail with truncated ciphertext', () => {
      const encrypted = aesgcm.encrypt(message, key);
      const truncated = encrypted.slice(0, -1); // Remove last byte
      
      expect(() => {
        aesgcm.decrypt(truncated, key);
      }).toThrow();
    });
  });

  describe('Industry standard compatibility', () => {
    it('should be deterministic with same key and nonce', () => {
      const fixedNonce = new Uint8Array(12).fill(42);
      
      const encrypted1 = aesgcm.encrypt(message, key, fixedNonce);
      const encrypted2 = aesgcm.encrypt(message, key, fixedNonce);
      
      expect(encrypted1).toEqual(encrypted2);
    });

    it('should work with random keys and messages', () => {
      const randomKey = randomBytes(32);
      const randomMessage = randomBytes(1000);
      
      const encrypted = aesgcm.encrypt(randomMessage, randomKey);
      const decrypted = aesgcm.decrypt(encrypted, randomKey);
      
      expect(decrypted).toEqual(randomMessage);
    });

    it('should have same overhead as ChaCha20-Poly1305', () => {
      const encrypted = aesgcm.encrypt(message, key);
      
      // Should have 28 bytes overhead (12-byte nonce + 16-byte tag)
      expect(encrypted.length).toBe(message.length + 28);
    });
  });

  describe('Performance', () => {
    it('should handle multiple encryptions efficiently', () => {
      const iterations = 100;
      const results = [];
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = aesgcm.encrypt(message, key);
        const decrypted = aesgcm.decrypt(encrypted, key);
        results.push(new TextDecoder().decode(decrypted));
      }
      
      expect(results).toHaveLength(iterations);
      expect(results.every(result => result === 'Hello, AES-GCM!')).toBe(true);
    });
  });
});
