// @ts-nocheck
import { sha256 } from '@noble/hashes/sha2.js';

const SCRIPT_CLASS_PUBKEY_DILITHIUM = 4;  // ScriptClass enum
const ACCOUNT_TX_VERSION = 0;
const LOCK_TIME = 0;
const SUBNETWORK_ID_ZERO = new Uint8Array(20);
const DEFAULT_GAS = 1000;

/* ═══════════════════════════════════════════
   Byte Helpers
   ═══════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════
   Build Script from Address Payload (20-byte hash)
   Format: [0x14, ...20 bytes, 0xac] = 22 bytes
   ═══════════════════════════════════════════ */

export function buildDilithiumScript(addressPayload: Uint8Array): Uint8Array {
  if (addressPayload.length !== 20) {
    throw new Error('Address payload must be 20 bytes');
  }
  const script = new Uint8Array(22);
  script[0] = 0x14;  // OP_PUSHBYTES_20
  script.set(addressPayload, 1);
  script[21] = 0xac; // OP_CHECKSIG
  return script;
}

/* ═══════════════════════════════════════════
   Compute Account Tx Sighash (EXACT match with Rust)
   
   sighash = SHA256(
     "SAHYADRI_ACCOUNT_TX_V1" ||
     version(u64 LE) ||
     [for each output:
        value(u64 LE) ||
        spk.version(u16 LE) ||
        spk.script.length(u64 LE) ||
        spk.script
     ] ||
     lock_time(u64 LE) ||
     subnetwork_id(20 bytes) ||
     gas(u64 LE) ||
     signable_payload.length(u64 LE) ||
     signable_payload
   )
   ═══════════════════════════════════════════ */

export function computeAccountTxSighash(
  senderPubkeyHex: string,
  receiverScript: Uint8Array,   // 22-byte script
  amountKana: number,            // u64
  nonce: number,                 // u64
  gas: number = DEFAULT_GAS
): Uint8Array {
  const parts: Uint8Array[] = [];

  // 1. Literal domain tag
  parts.push(new TextEncoder().encode('SAHYADRI_ACCOUNT_TX_V1'));

  // 2. tx.version (u64 LE)
  parts.push(u64LE(ACCOUNT_TX_VERSION));

  // 3. Outputs array (only 1 output)
  //    - output.value (u64 LE)
  parts.push(u64LE(amountKana));
  //    - output.script_public_key.version (u16 LE)
  parts.push(u16LE(SCRIPT_CLASS_PUBKEY_DILITHIUM));
  //    - output.script_public_key.script.length (u64 LE)
  parts.push(u64LE(receiverScript.length));
  //    - output.script_public_key.script (bytes)
  parts.push(receiverScript);

  // 4. tx.lock_time (u64 LE)
  parts.push(u64LE(LOCK_TIME));

  // 5. tx.subnetwork_id (20 zero bytes)
  parts.push(SUBNETWORK_ID_ZERO);

  // 6. tx.gas (u64 LE)
  parts.push(u64LE(gas));

  // 7. signable_payload = sender_pubkey || nonce_LE
  const senderPubkey = hexToBytes(senderPubkeyHex);
  const signablePayload = concat(senderPubkey, u64LE(nonce));

  // 8. signable_payload.length (u64 LE)
  parts.push(u64LE(signablePayload.length));

  // 9. signable_payload bytes
  parts.push(signablePayload);

  // 10. SHA256 of all
  return sha256(concat(...parts));
}
