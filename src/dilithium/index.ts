// @ts-nocheck
/**
 * Dilithium3 (ML-DSA-65) - Deterministic Keygen from BIP-39 Seed
 * Using @noble/post-quantum - audited FIPS 204
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { mnemonicToSeedSync } from 'bip39';

/* ═══════════════════════════════════════════
   RANDOM KEYPAIR (for testing only)
   ═══════════════════════════════════════════ */
export function keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keys = ml_dsa65.keygen();
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/* ═══════════════════════════════════════════
   DETERMINISTIC KEYPAIR FROM MNEMONIC
   Same mnemonic = Same keys = Same address (ALWAYS)
   ═══════════════════════════════════════════ */
export function keypairFromMnemonic(mnemonic: string): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  // Step 1: BIP-39 mnemonic → 64-byte seed
  const seed64 = mnemonicToSeedSync(mnemonic.trim().toLowerCase());
  
  // Step 2: First 32 bytes Dilithium ke liye
  const seed32 = new Uint8Array(seed64.slice(0, 32));
  
  // Step 3: Deterministic keygen (FIPS 204)
  const keys = ml_dsa65.keygen(seed32);
  
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/* ═══════════════════════════════════════════
   SIGN
   ═══════════════════════════════════════════ */
export function sign(
  secretKey: Uint8Array,
  message: Uint8Array
): Uint8Array {
  return ml_dsa65.sign(secretKey, message);
}

/* ═══════════════════════════════════════════
   VERIFY
   ═══════════════════════════════════════════ */
export function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array
): boolean {
  try {
    return ml_dsa65.verify(publicKey, message, signature);
  } catch (e) {
    return false;
  }
}
