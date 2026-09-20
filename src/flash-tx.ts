// @ts-nocheck
/**
 * Sahyadri Flash Transaction (SFT) — nonce-less tx builder.
 *
 * MUST match consensus/core/src/tx.rs byte-for-byte:
 *   - flash_id()  — domain "SAHYADRI_FLASH_ID_V1"
 *   - sighash()   — domain "SAHYADRI_FLASH_TX_V1"
 *   - to_transaction() — magic prefix "FLASH_V1"
 *
 * Any field order / byte-order change here MUST be mirrored in Rust.
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { sign } from './dilithium/index';

// ═══════════════════════════════════════════
// CONSTANTS — must match Rust tx.rs
// ═══════════════════════════════════════════
export const FLASH_VERSION: number = 0;
export const FLASH_MAGIC: Uint8Array = new TextEncoder().encode('FLASH_V1');
const FLASH_ID_DOMAIN = 'SAHYADRI_FLASH_ID_V1';
const FLASH_SIGHASH_DOMAIN = 'SAHYADRI_FLASH_TX_V1';

/**
 * Buffer added to current DAA score to compute expiry_daa_score.
 * Not exactly 100 — network round-trip + block time means the actual
 * DAA score advances between RPC fetch and block inclusion.
 * 90 gives ~10 blocks of safety margin.
 */
export const FLASH_EXPIRY_BUFFER: bigint = 90n;

// ═══════════════════════════════════════════
// BYTE HELPERS
// ═══════════════════════════════════════════
function u16LE(n: number): Uint8Array {
  const buf = new Uint8Array(2);
  new DataView(buf.buffer).setUint16(0, n, true);
  return buf;
}

function u32LE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, true);
  return buf;
}

function u64LE(n: bigint | number): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(n), true);
  return buf;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * Cryptographically secure 16-byte salt.
 * Uses WebCrypto (browser + Node 19+) — never Math.random().
 */
export function randomFlashSalt(): Uint8Array {
  const salt = new Uint8Array(16);
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(salt);
  } else {
    throw new Error('Secure RNG unavailable — crypto.getRandomValues required');
  }
  return salt;
}

// ═══════════════════════════════════════════
// FLASH ID + SIGHASH
// ═══════════════════════════════════════════

export interface FlashTxFields {
  version: number;
  pubkey: Uint8Array;      // 1952 bytes
  recipient: Uint8Array;   // 20 bytes (address payload hash)
  amount: bigint;
  fee: bigint;
  expiryDaaScore: bigint;
  salt: Uint8Array;        // 16 bytes
}

/**
 * Computes flash_id — deterministic unique identifier.
 * MUST match Rust FlashTransaction::flash_id().
 */
export function computeFlashId(fields: FlashTxFields): Uint8Array {
  const parts: Uint8Array[] = [
    new TextEncoder().encode(FLASH_ID_DOMAIN),
    u16LE(fields.version),
    fields.pubkey,
    fields.recipient,
    u64LE(fields.amount),
    u64LE(fields.fee),
    u64LE(fields.expiryDaaScore),
    fields.salt,
  ];
  return sha3_256(concat(...parts));
}

/**
 * Computes sighash — what gets signed.
 * MUST match Rust FlashTransaction::sighash().
 */
export function computeFlashSighash(fields: FlashTxFields): Uint8Array {
  const parts: Uint8Array[] = [
    new TextEncoder().encode(FLASH_SIGHASH_DOMAIN),
    u16LE(fields.version),
    fields.pubkey,
    fields.recipient,
    u64LE(fields.amount),
    u64LE(fields.fee),
    u64LE(fields.expiryDaaScore),
    fields.salt,
  ];
  return sha3_256(concat(...parts));
}

// ═══════════════════════════════════════════
// BUILDER
// ═══════════════════════════════════════════

export interface BuildFlashTxParams {
  /** Sender's ML-DSA-65 secret key (4032 bytes) */
  secretKey: Uint8Array;
  /** Sender's ML-DSA-65 public key (1952 bytes) */
  publicKey: Uint8Array;
  /** Receiver's 20-byte address hash (from decodeAddressPayload(addr).slice(1)) */
  recipient: Uint8Array;
  /** Amount in kana (1 CSM = 10^8) */
  amount: bigint;
  /** Fee in kana (min 1000) */
  fee: bigint;
  /** Current DAA score from node RPC */
  currentDaaScore: bigint;
}

/**
 * Builds a signed FlashTransaction and returns the serialized bytes
 * ready to be wrapped in a `Transaction` with `FLASH_V1` magic prefix.
 */
export function buildFlashTransaction(params: BuildFlashTxParams): Uint8Array {
  if (params.recipient.length !== 20) {
    throw new Error(`recipient must be 20 bytes, got ${params.recipient.length}`);
  }
  if (params.publicKey.length !== 1952) {
    throw new Error(`pubkey must be 1952 bytes, got ${params.publicKey.length}`);
  }

  const salt = randomFlashSalt();
  const expiryDaaScore = params.currentDaaScore + FLASH_EXPIRY_BUFFER;

  const fields: FlashTxFields = {
    version: FLASH_VERSION,
    pubkey: params.publicKey,
    recipient: params.recipient,
    amount: params.amount,
    fee: params.fee,
    expiryDaaScore,
    salt,
  };

  const sighash = computeFlashSighash(fields);

  // FIPS 204 ML-DSA-65 sign — matches node's DilithiumKeyPair::verify
  // with empty context (b"")
  const signature = sign(params.secretKey, sighash);

  // Serialize: magic || version || pubkey || recipient || amount || fee
  //           || expiry || salt || signature
  // (order matches FlashTransaction::to_transaction() in tx.rs)
  const serialized = concat(
    FLASH_MAGIC,
    u16LE(fields.version),
    u32LE(fields.pubkey.length), fields.pubkey,
    u32LE(fields.recipient.length), fields.recipient,
    u64LE(fields.amount),
    u64LE(fields.fee),
    u64LE(fields.expiryDaaScore),
    fields.salt,
    u32LE(signature.length), signature,
  );

  return serialized;
}

/**
 * Serialized layout for callers who want to send via RPC.
 * Returns hex string of the encoded payload (to embed in Transaction.payload).
 */
export function buildFlashTransactionHex(params: BuildFlashTxParams): string {
  const bytes = buildFlashTransaction(params);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ═══════════════════════════════════════════
// EXPORTS FOR WALLET
// ═══════════════════════════════════════════
export const FLASH_TX_DEFAULTS = {
  MIN_FEE_KANA: 1000n,
  /** Per RPC getDaaScore */
  getExpiryFor: (current: bigint) => current + FLASH_EXPIRY_BUFFER,
};
