// @ts-nocheck
/**
 * Dilithium3 (ML-DSA-65) - Deterministic Keygen from BIP-39 Seed
 * Using @noble/post-quantum - audited FIPS 204
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { mnemonicToSeedSync } from 'bip39';

/* ═══════════════════════════════════════════
   KEYPAIR GENERATION
   ═══════════════════════════════════════════ */
export function keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keys = ml_dsa65.keygen();
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

export function keypairFromMnemonic(mnemonic: string): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  const seed64 = mnemonicToSeedSync(mnemonic.trim().toLowerCase());
  const seed32 = new Uint8Array(seed64.slice(0, 32));
  const keys = ml_dsa65.keygen(seed32);
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/* ═══════════════════════════════════════════
   SIGN - @noble API: sign(message, secretKey)
   ═══════════════════════════════════════════ */
export function sign(
  secretKey: Uint8Array,
  message: Uint8Array
): Uint8Array {
  // @noble API: sign(message, secretKey)
  return ml_dsa65.sign(message, secretKey);
}

/* ═══════════════════════════════════════════
   VERIFY - @noble API: verify(signature, message, publicKey)
   ═══════════════════════════════════════════ */
export function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array
): boolean {
  try {
    // @noble API: verify(signature, message, publicKey)
    return ml_dsa65.verify(signature, message, publicKey);
  } catch (e) {
    return false;
  }
}
