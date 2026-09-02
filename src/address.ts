// @ts-nocheck
import { bech32 } from '@scure/base';
import { sha3 } from './sha3';

const PREFIX_MAIN = 'csm';
const PREFIX_TEST = 'csmtest';

function pubkeyToHash(pk: Uint8Array): Uint8Array {
  // Node: PubKeyDilithium = 20-byte SHA256 hash of full Dilithium public key
  return sha3(pk).slice(0, 20);
}

export function pubkeyToAddress(pk: Uint8Array, testnet = false): string {
  const hash = pubkeyToHash(pk);
  // Version 129 = PubKeyDilithium
  const version = new Uint8Array([129]);
  const payload = new Uint8Array(version.length + hash.length);
  payload.set(version, 0);
  payload.set(hash, version.length);
  const words = bech32.toWords(payload);
  return bech32.encode(testnet ? PREFIX_TEST : PREFIX_MAIN, words);
}

export function isValidAddress(addr: string, testnet = false): boolean {
  try {
    const { prefix, words } = bech32.decode(addr);
    if (prefix !== (testnet ? PREFIX_TEST : PREFIX_MAIN)) return false;
    const data = bech32.fromWords(words);
    return data.length === 21 && data[0] === 129;
  } catch {
    return false;
  }
}
