import { sha3_256, shake256, shake128 } from '@noble/hashes/sha3';

export class DomainHasher {
  private init: Uint8Array;
  constructor(domain: string) {
    this.init = new Uint8Array(sha3_256(new TextEncoder().encode(domain)));
  }
  hash(data: Uint8Array): Uint8Array {
    const h = sha3_256.create();
    h.update(this.init);
    h.update(data);
    return new Uint8Array(h.digest());
  }
  clone(): DomainHasher {
    const d = new DomainHasher('');
    d.init = new Uint8Array(this.init);
    return d;
  }
}

export const TxHash = new DomainHasher('TransactionHash');
export const TxID = new DomainHasher('TransactionID');
export const TxSigningHash = new DomainHasher('TransactionSigningHash');
export const BlockHash = new DomainHasher('BlockHash');
export const MerkleHash = new DomainHasher('MerkleBranchHash');

export function sha3(data: Uint8Array): Uint8Array {
  return new Uint8Array(sha3_256(data));
}

export function shake256Bytes(data: Uint8Array, len: number): Uint8Array {
  return new Uint8Array(shake256(data, { dkLen: len }));
}

export function shake128Bytes(data: Uint8Array, len: number): Uint8Array {
  return new Uint8Array(shake128(data, { dkLen: len }));
}

// cSHAKE256 for Dilithium3 signing - uses shake256 imported at line 1
export function shake256Digest(data: Uint8Array, outputLen: number): Uint8Array {
  return new Uint8Array(shake256(data, { dkLen: outputLen }));
}
