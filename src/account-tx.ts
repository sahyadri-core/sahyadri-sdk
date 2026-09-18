// @ts-nocheck
import { sha256 } from '@noble/hashes/sha2.js';

const SCRIPT_CLASS_PUBKEY_DILITHIUM = 0;  // Node uses MAX_SCRIPT_PUBLIC_KEY_VERSION = 0
const ACCOUNT_TX_VERSION = 0;
const LOCK_TIME = 0;
const SUBNETWORK_ID_ZERO = new Uint8Array(20);
const DEFAULT_GAS = 1000;

function u64LE(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(n), true);
  return buf;
}

function u16LE(n: number): Uint8Array {
  const buf = new Uint8Array(2);
  const view = new DataView(buf.buffer);
  view.setUint16(0, n, true);
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

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
}

export function buildDilithiumScript(addressPayload: Uint8Array): Uint8Array {
  if (addressPayload.length !== 20) {
    throw new Error('Address payload must be 20 bytes');
  }
  const script = new Uint8Array(22);
  script[0] = 0x14;
  script.set(addressPayload, 1);
  script[21] = 0xac;
  return script;
}

export function computeAccountTxSighash(
  senderPubkeyHex: string,
  receiverScript: Uint8Array,
  amountKana: number,
  nonce: number,
  gas: number = DEFAULT_GAS
): Uint8Array {
  const parts: Uint8Array[] = [];

  parts.push(new TextEncoder().encode('SAHYADRI_ACCOUNT_TX_V1'));
  parts.push(u16LE(ACCOUNT_TX_VERSION));
  parts.push(u64LE(amountKana));
  parts.push(u16LE(SCRIPT_CLASS_PUBKEY_DILITHIUM));
  parts.push(u64LE(receiverScript.length));
  parts.push(receiverScript);
  parts.push(u64LE(LOCK_TIME));
  parts.push(SUBNETWORK_ID_ZERO);
  parts.push(u64LE(gas));

  const senderPubkey = hexToBytes(senderPubkeyHex);
  const signablePayload = concat(senderPubkey, u64LE(nonce));
  parts.push(u64LE(signablePayload.length));
  parts.push(signablePayload);

  return sha256(concat(...parts));
}

/* ═══════════════════════════════════════════
   NODE-KOMPATIBLE ML-DSA SIGN
   Node prefixes message with [0x00, ctx_len] || ctx
   (ctx = empty, so prefix = [0x00, 0x00])
   ═══════════════════════════════════════════ */

export function prefixMessageForNode(message: Uint8Array): Uint8Array {
  // FIPS 204: M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || M
  const prefix = new Uint8Array([0x00, 0x00]); // domain=0, ctx_len=0
  const result = new Uint8Array(prefix.length + message.length);
  result.set(prefix, 0);
  result.set(message, prefix.length);
  return result;
}
