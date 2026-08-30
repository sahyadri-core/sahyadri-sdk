// @ts-nocheck
/**
 * Hash Functions for Sahyadri SDK
 * Using @noble/hashes (audited crypto) - ESM only!
 */
import { sha3_256, shake256 } from '@noble/hashes/sha3.js';

export class DomainHasher {
  constructor(private domain: string) {}
  
  hash(data: Uint8Array): Uint8Array {
    const domainBytes = new TextEncoder().encode(this.domain);
    const combined = new Uint8Array(domainBytes.length + data.length);
    combined.set(domainBytes, 0);
    combined.set(data, domainBytes.length);
    return sha3_256(combined);
  }
}

export const TxHash = new DomainHasher('TransactionHash');
export const TxID = new DomainHasher('TransactionID');
export const TxSigningHash = new DomainHasher('TransactionSigningHash');
export const BlockHash = new DomainHasher('BlockHash');
export const MerkleHash = new DomainHasher('MerkleBranchHash');

// SHA3-256 (standard)
export function sha3(data: Uint8Array): Uint8Array {
  return sha3_256(data);
}

// SHAKE256 (extendable output)
export function shake256Bytes(data: Uint8Array, len: number): Uint8Array {
  return shake256.create({ dkLen: len }).update(data).digest();
}

// SHAKE128  
export function shake128Bytes(data: Uint8Array, len: number): Uint8Array {
  return shake256.create({ dkLen: len }).update(data).digest();
}

// Alias
export function shake256Digest(data: Uint8Array, outputLen: number): Uint8Array {
  return shake256Bytes(data, outputLen);
}
