import { describe, it, expect } from '@scintilla-network/litest';
import { chacha20 } from './chacha20.js';
import { randomBytes } from '../../utils/index.js';

describe('ChaCha20-Poly1305 (TLS 1.3)', () => {
  const key = new Uint8Array(32).fill(1); // Deterministic key for testing
  const message = new TextEncoder().encode('Hello, ChaCha20-Poly1305!');

  describe('Basic encrypt/decrypt', () => {
    it('should encrypt and decrypt successfully with auto-generated nonce', () => {
      const encrypted = chacha20.encrypt(message, key);
      const decrypted = chacha20.decrypt(encrypted, key);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, ChaCha20-Poly1305!');
    });

    it('should encrypt and decrypt with custom nonce', () => {
      const customNonce = new Uint8Array(12).fill(42); // 12-byte nonce for ChaCha20
      const encrypted = chacha20.encrypt(message, key, customNonce);
      const decrypted = chacha20.decrypt(encrypted, key);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, ChaCha20-Poly1305!');
    });

    it('should decrypt with explicit nonce parameter', () => {
      const customNonce = new Uint8Array(12).fill(99);
      const encrypted = chacha20.encrypt(message, key, customNonce);
      
      // Extract ciphertext without nonce
      const ciphertext = encrypted.slice(12);
      const decrypted = chacha20.decrypt(ciphertext, key, customNonce);
      
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, ChaCha20-Poly1305!');
    });
  });

  describe('Nonce handling', () => {
    it('should prepend nonce to encrypted data', () => {
      const customNonce = new Uint8Array(12).fill(123);
      const encrypted = chacha20.encrypt(message, key, customNonce);
      
      // First 12 bytes should be the nonce
      const extractedNonce = encrypted.slice(0, 12);
      expect(extractedNonce).toEqual(customNonce);
    });

    it('should generate different nonces for each encryption', () => {
      const encrypted1 = chacha20.encrypt(message, key);
      const encrypted2 = chacha20.encrypt(message, key);
      
      const nonce1 = encrypted1.slice(0, 12);
      const nonce2 = encrypted2.slice(0, 12);
      
      expect(nonce1).not.toEqual(nonce2);
    });

    it('should use 12-byte nonces (TLS 1.3 standard)', () => {
      const encrypted = chacha20.encrypt(message, key);
      
      // ChaCha20-Poly1305 uses 12-byte nonces (same as AES-GCM)
      expect(encrypted.length).toBeGreaterThanOrEqual(12 + message.length + 16); // nonce + message + tag
    });
  });

  describe('Data integrity', () => {
    it('should handle empty messages', () => {
      const emptyMessage = new Uint8Array(0);
      const encrypted = chacha20.encrypt(emptyMessage, key);
      const decrypted = chacha20.decrypt(encrypted, key);
      
      expect(decrypted).toEqual(emptyMessage);
    });

    it('should handle large messages', () => {
      const largeMessage = new Uint8Array(10000).fill(255);
      const encrypted = chacha20.encrypt(largeMessage, key);
      const decrypted = chacha20.decrypt(encrypted, key);
      
      expect(decrypted).toEqual(largeMessage);
    });

    it('should produce different ciphertexts for same message with different nonces', () => {
      const nonce1 = new Uint8Array(12).fill(1);
      const nonce2 = new Uint8Array(12).fill(2);
      
      const encrypted1 = chacha20.encrypt(message, key, nonce1);
      const encrypted2 = chacha20.encrypt(message, key, nonce2);
      
      expect(encrypted1).not.toEqual(encrypted2);
    });
  });

  describe('Error handling', () => {
    it('should fail with wrong key', () => {
      const wrongKey = new Uint8Array(32).fill(2);
      const encrypted = chacha20.encrypt(message, key);
      
      expect(() => {
        chacha20.decrypt(encrypted, wrongKey);
      }).toThrow();
    });

    it('should fail with corrupted ciphertext', () => {
      const encrypted = chacha20.encrypt(message, key);
      encrypted[encrypted.length - 1] ^= 1; // Flip a bit in the tag
      
      expect(() => {
        chacha20.decrypt(encrypted, key);
      }).toThrow();
    });

    it('should fail with truncated ciphertext', () => {
      const encrypted = chacha20.encrypt(message, key);
      const truncated = encrypted.slice(0, -1); // Remove last byte
      
      expect(() => {
        chacha20.decrypt(truncated, key);
      }).toThrow();
    });
  });

  describe('TLS 1.3 compatibility', () => {
    it('should be deterministic with same key and nonce', () => {
      const fixedNonce = new Uint8Array(12).fill(42);
      
      const encrypted1 = chacha20.encrypt(message, key, fixedNonce);
      const encrypted2 = chacha20.encrypt(message, key, fixedNonce);
      
      expect(encrypted1).toEqual(encrypted2);
    });

    it('should use same nonce size as AES-GCM (12 bytes)', () => {
      const encrypted = chacha20.encrypt(message, key);
      const nonce = encrypted.slice(0, 12);
      
      expect(nonce).toHaveLength(12);
    });

    it('should work with random keys and messages', () => {
      const randomKey = randomBytes(32);
      const randomMessage = randomBytes(1000);
      
      const encrypted = chacha20.encrypt(randomMessage, randomKey);
      const decrypted = chacha20.decrypt(encrypted, randomKey);
      
      expect(decrypted).toEqual(randomMessage);
    });
  });

  describe('Performance', () => {
    it('should handle multiple encryptions efficiently', () => {
      const iterations = 100;
      const results = [];
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = chacha20.encrypt(message, key);
        const decrypted = chacha20.decrypt(encrypted, key);
        results.push(new TextDecoder().decode(decrypted));
      }
      
      expect(results).toHaveLength(iterations);
      expect(results.every(result => result === 'Hello, ChaCha20-Poly1305!')).toBe(true);
    });
  });
});
