// @ts-nocheck
/**
 * Dilithium3 (ML-DSA-65) Implementation  
 * Using @noble/post-quantum - audited FIPS 204
 * 
 * API:
 *   sign(message, secretKey)
 *   verify(signature, message, publicKey)
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

/* ═══════════════════════════════════════════
   KEYPAIR GENERATION
   ═══════════════════════════════════════════ */

export function keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keys = ml_dsa65.keygen();
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey
  };
}

/* ═══════════════════════════════════════════
   SIGN (message, secretKey)
   ═══════════════════════════════════════════ */

export function sign(
  secretKey: Uint8Array, 
  message: Uint8Array
): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

/* ═══════════════════════════════════════════
   VERIFY (signature, message, publicKey)
   ═══════════════════════════════════════════ */

export function verify(
  publicKey: Uint8Array, 
  signature: Uint8Array, 
  message: Uint8Array
): boolean {
  // @noble/post-quantum uses verify(signature, message, publicKey)
  return ml_dsa65.verify(signature, message, publicKey);
}
