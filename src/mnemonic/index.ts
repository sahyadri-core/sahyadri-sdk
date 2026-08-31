/**
 * Sahyadri Mnemonic / Seed Phrase Module
 * BIP-39 Compatible for wallet backup & recovery
 * Uses Node.js built-in crypto (no external dependencies)
 */

import { wordlist } from './wordlist.js';
import * as crypto from 'node:crypto';

const BIP39_WORDLIST: readonly string[] = wordlist;

/**
 * Generate a BIP-39 compatible mnemonic seed phrase
 * @param strength - Entropy in bits (128 = 12 words, 256 = 24 words)
 * @returns Space-separated mnemonic string
 */
export function generateMnemonic(strength: 128 | 160 | 192 | 224 | 256 = 128): string {
  const allowedStrengths = [128, 160, 192, 224, 256];
  if (!allowedStrengths.includes(strength)) {
    throw new Error(`Invalid entropy strength. Must be one of: ${allowedStrengths.join(', ')}`);
  }

  // Generate random entropy
  const entropy = crypto.randomBytes(strength / 8);
  
  return entropyToMnemonic(entropy);
}

/**
 * Convert entropy bytes to mnemonic phrase
 */
function entropyToMnemonic(entropy: Buffer): string {
  const entropyBits = bytesToBinary(entropy);
  
  // Calculate checksum length (entropy length / 32)
  const checksumBits = entropy.length / 4;
  
  // Add checksum
  const hash = crypto.createHash('sha256').update(entropy).digest();
  const hashBits = bytesToBinary(hash);
  
  const fullEntropyBits = entropyBits + hashBits.slice(0, checksumBits);
  
  // Split into 11-bit chunks and map to words
  const chunks: string[] = [];
  for (let i = 0; i < fullEntropyBits.length; i += 11) {
    const index = parseInt(fullEntropyBits.slice(i, i + 11), 2);
    chunks.push(BIP39_WORDLIST[index]);
  }
  
  return chunks.join(' ');
}

/**
 * Validate a BIP-39 mnemonic phrase
 * @param mnemonic - Space-separated mnemonic string
 * @returns true if valid BIP-39 mnemonic
 */
export function validateMnemonic(mnemonic: string): boolean {
  try {
    const words = normalizeMnemonic(mnemonic).split(' ');
    
    // Check word count (must be 12, 15, 18, 21, or 24)
    if (![12, 15, 18, 21, 24].includes(words.length)) {
      return false;
    }
    
    // All words must be in wordlist
    for (const word of words) {
      if (!BIP39_WORDLIST.includes(word)) {
        return false;
      }
    }
    
    // Reconstruct entropy from words
    let bits = '';
    for (const word of words) {
      const index = BIP39_WORDLIST.indexOf(word);
      if (index === -1) return false;
      bits += index.toString(2).padStart(11, '0');
    }
    
    // Split into entropy + checksum
    const divider = bits.length / 33;
    const entropyBits = bits.slice(0, divider * 32);
    const checksumBits = bits.slice(divider * 32);
    
    // Verify checksum
    const entropyBytes = binaryToBytes(entropyBits);
    const hash = crypto.createHash('sha256').update(entropyBytes).digest();
    const hashBits = bytesToBinary(hash);
    
    // Compare first checksumLength bits
    return hashBits.slice(0, checksumBits.length) === checksumBits;
  } catch {
    return false;
  }
}

/**
 * Convert mnemonic to binary seed using PBKDF2
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param password - Optional passphrase (default: empty string)
 * @returns 64-byte seed
 */
export function mnemonicToSeed(
  mnemonic: string, 
  password: string = ''
): Buffer {
  const normalizedMnemonic = normalizeMnemonic(mnemonic);
  const salt = normalizeString('mnemonic' + password);
  
  return crypto.pbkdf2Sync(
    normalizedMnemonic,
    salt,
    2048,   // iterations
    64,     // key length (bytes)
    'sha256'
  );
}

/**
 * Synchronous version (same as above - pbkdf2Sync is already sync)
 */
export function mnemonicToSeedSync(
  mnemonic: string,
  password: string = ''
): Buffer {
  return mnemonicToSeed(mnemonic, password);
}

/**
 * Normalize mnemonic (handle extra spaces, newlines, etc.)
 */
function normalizeMnemonic(mnemonic: string): string {
  return mnemonic
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .normalize('NFKD');
}

/**
 * Normalize string for PBKDF2
 */
function normalizeString(str: string): string {
  return str.normalize('NFKD');
}

/**
 * Convert byte array to binary string
 */
function bytesToBinary(bytes: Buffer | Uint8Array): string {
  return [...bytes]
    .map(b => b.toString(2).padStart(8, '0'))
    .join('');
}

/**
 * Convert binary string to byte array
 */
function binaryToBytes(binary: string): Buffer {
  const bytes = Buffer.alloc(binary.length / 8);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(binary.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}
