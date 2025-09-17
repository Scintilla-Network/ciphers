import { aesgcm, chacha20, xchacha20, utils } from './src/index.js';

const message = new TextEncoder().encode("Hello World! This is a secret message.");

const key = utils.randomBytes(32);

const xchachaEncrypted = xchacha20.encrypt(key, message);
const xchachaDecrypted = xchacha20.decrypt(key, xchachaEncrypted);
const xchachaResult = new TextDecoder().decode(xchachaDecrypted);
console.log("XChaCha20-Poly1305 Result:", xchachaResult);
console.log("XChaCha20-Poly1305 Encrypted size:", xchachaEncrypted.length, "bytes (overhead:", xchachaEncrypted.length - message.length, "bytes) \n");

const aesEncrypted = aesgcm.encrypt(key, message);
const aesDecrypted = aesgcm.decrypt(key, aesEncrypted);
const aesResult = new TextDecoder().decode(aesDecrypted);
console.log("AES-GCM Result:", aesResult);
console.log("AES-GCM Encrypted size:", aesEncrypted.length, "bytes (overhead:", aesEncrypted.length - message.length, "bytes) \n");


const chachaEncrypted = chacha20.encrypt(key, message);
const chachaDecrypted = chacha20.decrypt(key, chachaEncrypted);
const chachaResult = new TextDecoder().decode(chachaDecrypted);
console.log("ChaCha20-Poly1305 Result:", chachaResult);
console.log("ChaCha20-Poly1305 Encrypted size:", chachaEncrypted.length, "bytes (overhead:", chachaEncrypted.length - message.length, "bytes) \n");




// Provide your own nonce if needed
const customNonce = utils.randomBytes(24); // XChaCha20 uses 24-byte nonces
const encrypted = xchacha20.encrypt(key, message, customNonce).slice(24); // We slice the nonce from the encrypted data
const decrypted = xchacha20.decrypt(key, encrypted, customNonce);
console.log("XChaCha20-Poly1305 Result:", new TextDecoder().decode(decrypted));
