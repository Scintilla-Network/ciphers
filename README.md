# @scintilla-network/ciphers

Simple, secure encryption for JavaScript. Easy nonce management - just encrypt and decrypt!

[![npm version](https://badge.fury.io/js/@scintilla-network%2Fciphers.svg)](https://www.npmjs.com/package/@scintilla-network/ciphers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

* 🧪 **XChaCha20-Poly1305** — Recommended for most use cases (safe with random nonces)
* 🔒 **AES-GCM** — Industry standard, widely supported
* ⚡ **ChaCha20-Poly1305** — Used in TLS 1.3.
* 🎯 **Simplified nonce management** — Library handles nonces automatically (still allows for custom nonces)
* 🔬 **Audited implementations** — Built on battle-tested noble-ciphers
* 📦 **Zero dependencies** beyond noble
* 🛡️ **256-bit security** — Post-quantum resistant (Grover's algorithm only gives a quadratic speedup)

## Installation

```bash
npm install @scintilla-network/ciphers
```

## Usage

### Quick Start (Recommended algorithm)

```javascript
import { xchacha20, utils } from '@scintilla-network/ciphers';

// Generate a random key
const key = utils.randomBytes(32);
// Convert the message to a Uint8Array
const message = new TextEncoder().encode("Hello World!");

// Encrypt (output is prepended with the nonce)
const encrypted = xchacha20.encrypt(message, key);

// Decrypt
const decrypted = xchacha20.decrypt(encrypted, key);
console.log(new TextDecoder().decode(decrypted)); // "Hello World!"
```

### All Available Ciphers

```javascript
import { xchacha20, aesgcm, chacha20, utils } from '@scintilla-network/ciphers';

const key = utils.randomBytes(32);
const message = new TextEncoder().encode("Secret message");

// XChaCha20-Poly1305 (recommended - safe with random nonces)
const encrypted1 = xchacha20.encrypt(message, key);
const decrypted1 = xchacha20.decrypt(encrypted1, key);

// AES-GCM (industry standard)
const encrypted2 = aesgcm.encrypt(message, key);
const decrypted2 = aesgcm.decrypt(encrypted2, key);

// ChaCha20-Poly1305 (TLS 1.3 standard)
const encrypted3 = chacha20.encrypt(message, key);
const decrypted3 = chacha20.decrypt(encrypted3, key);
```

### Custom Nonces (Advanced)

```javascript
import { xchacha20, utils } from '@scintilla-network/ciphers';

const key = utils.randomBytes(32);
const message = new TextEncoder().encode("Hello World!");

// Provide your own nonce if needed
const customNonce = utils.randomBytes(24); // XChaCha20 uses 24-byte nonces
const encrypted = xchacha20.encrypt(message, key, customNonce).slice(24); // We slice the nonce off from the encrypted data
const decrypted = xchacha20.decrypt(encrypted, key, customNonce);
```

## Why XChaCha20-Poly1305?

**XChaCha20-Poly1305 is recommended for most applications** because:

* ✅ **Safe with random nonces** - No need to track nonce uniqueness
* ✅ **Large nonce space** - 24 bytes means virtually no collision risk
* ✅ **Fast performance** - Often faster than AES in JavaScript
* ✅ **Modern design** - Built for today's security needs

**When to use others:**
* **AES-GCM**: When you need maximum compatibility or hardware acceleration
* **ChaCha20-Poly1305**: When building TLS 1.3 compatible systems (is standardized in TLS 1.3)

## Related Packages

* [@scintilla-network/hashes](https://github.com/Scintilla-Network/hashes): Hashes, KDFs, utilities
* [@scintilla-network/signatures](https://github.com/Scintilla-Network/signatures): Signatures and key exchange

## License

MIT License - see the [LICENSE](LICENSE) file for details

## Credits

This library builds upon the excellent work of:
- [noble-ciphers](https://github.com/paulmillr/noble-ciphers) by Paul Miller