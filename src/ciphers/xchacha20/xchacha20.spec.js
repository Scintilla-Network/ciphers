import { describe, it, expect } from 'vitest';
import { xchacha20 } from './xchacha20.js';
import { randomBytes } from '../utils/index.js';

describe('XChaCha20-Poly1305', () => {
  const key = new Uint8Array(32).fill(1); // Deterministic key for testing
  const message = new TextEncoder().encode('Hello, XChaCha20-Poly1305!');

  describe('Basic encrypt/decrypt', () => {
    it('should encrypt and decrypt successfully with auto-generated nonce', () => {
      const encrypted = xchacha20.encrypt(key, message);
      const decrypted = xchacha20.decrypt(key, encrypted);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, XChaCha20-Poly1305!');
    });

    it('should encrypt and decrypt with custom nonce', () => {
      const customNonce = new Uint8Array(24).fill(42); // 24-byte nonce for XChaCha20
      const encrypted = xchacha20.encrypt(key, message, customNonce);
      const decrypted = xchacha20.decrypt(key, encrypted);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, XChaCha20-Poly1305!');
    });

    it('should decrypt with explicit nonce parameter', () => {
      const customNonce = new Uint8Array(24).fill(99);
      const encrypted = xchacha20.encrypt(key, message, customNonce);
      
      // Extract ciphertext without nonce
      const ciphertext = encrypted.slice(24);
      const decrypted = xchacha20.decrypt(key, ciphertext, customNonce);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, XChaCha20-Poly1305!');
    });
  });

  describe('Nonce handling', () => {
    it('should prepend nonce to encrypted data', () => {
      const customNonce = new Uint8Array(24).fill(123);
      const encrypted = xchacha20.encrypt(key, message, customNonce);
      
      // First 24 bytes should be the nonce
      const extractedNonce = encrypted.slice(0, 24);
      expect(extractedNonce).toEqual(customNonce);
    });

    it('should generate different nonces for each encryption', () => {
      const encrypted1 = xchacha20.encrypt(key, message);
      const encrypted2 = xchacha20.encrypt(key, message);
      
      const nonce1 = encrypted1.slice(0, 24);
      const nonce2 = encrypted2.slice(0, 24);
      
      expect(nonce1).not.toEqual(nonce2);
    });

    it('should use 24-byte nonces', () => {
      const encrypted = xchacha20.encrypt(key, message);
      
      // XChaCha20 uses 24-byte nonces
      expect(encrypted.length).toBeGreaterThanOrEqual(24 + message.length + 16); // nonce + message + tag
    });
  });

  describe('Data integrity', () => {
    it('should handle empty messages', () => {
      const emptyMessage = new Uint8Array(0);
      const encrypted = xchacha20.encrypt(key, emptyMessage);
      const decrypted = xchacha20.decrypt(key, encrypted);
      
      expect(decrypted).toEqual(emptyMessage);
    });

    it('should handle large messages', () => {
      const largeMessage = new Uint8Array(10000).fill(255);
      const encrypted = xchacha20.encrypt(key, largeMessage);
      const decrypted = xchacha20.decrypt(key, encrypted);
      
      expect(decrypted).toEqual(largeMessage);
    });

    it('should produce different ciphertexts for same message with different nonces', () => {
      const nonce1 = new Uint8Array(24).fill(1);
      const nonce2 = new Uint8Array(24).fill(2);
      
      const encrypted1 = xchacha20.encrypt(key, message, nonce1);
      const encrypted2 = xchacha20.encrypt(key, message, nonce2);
      
      expect(encrypted1).not.toEqual(encrypted2);
    });
  });

  describe('Error handling', () => {
    it('should fail with wrong key', () => {
      const wrongKey = new Uint8Array(32).fill(2);
      const encrypted = xchacha20.encrypt(key, message);
      
      expect(() => {
        xchacha20.decrypt(wrongKey, encrypted);
      }).toThrow();
    });

    it('should fail with corrupted ciphertext', () => {
      const encrypted = xchacha20.encrypt(key, message);
      encrypted[encrypted.length - 1] ^= 1; // Flip a bit in the tag
      
      expect(() => {
        xchacha20.decrypt(key, encrypted);
      }).toThrow();
    });

    it('should fail with truncated ciphertext', () => {
      const encrypted = xchacha20.encrypt(key, message);
      const truncated = encrypted.slice(0, -1); // Remove last byte
      
      expect(() => {
        xchacha20.decrypt(key, truncated);
      }).toThrow();
    });
  });

  describe('Compatibility', () => {
    it('should be deterministic with same key and nonce', () => {
      const fixedNonce = new Uint8Array(24).fill(42);
      
      const encrypted1 = xchacha20.encrypt(key, message, fixedNonce);
      const encrypted2 = xchacha20.encrypt(key, message, fixedNonce);
      
      expect(encrypted1).toEqual(encrypted2);
    });

    it('should work with random keys and messages', () => {
      const randomKey = randomBytes(32);
      const randomMessage = randomBytes(1000);
      
      const encrypted = xchacha20.encrypt(randomKey, randomMessage);
      const decrypted = xchacha20.decrypt(randomKey, encrypted);
      
      expect(decrypted).toEqual(randomMessage);
    });
  });

  describe('Performance', () => {
    it('should handle multiple encryptions efficiently', () => {
      const iterations = 100;
      const results = [];
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = xchacha20.encrypt(key, message);
        const decrypted = xchacha20.decrypt(key, encrypted);
        results.push(new TextDecoder().decode(decrypted));
      }
      
      expect(results).toHaveLength(iterations);
      expect(results.every(result => result === 'Hello, XChaCha20-Poly1305!')).toBe(true);
    });
  });
});
