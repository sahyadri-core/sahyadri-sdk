// @ts-nocheck
/**
 * Sahyadri Address Generation (CSM32 Bech32 Format)
 * Converts ML-DSA-65 public key to csm1s... addresses
 */
import { bech32 } from '@scure/base';
import { sha3 } from './sha3';

const PREFIX_MAIN = 'csm1s';  // Mainnet: csm1s...
const PREFIX_TEST = 'tcsms';  // Testnet: tcsms...

function pubkeyToHash(pk: Uint8Array): Uint8Array {
  return sha3(pk).slice(0, 20);
}

export function pubkeyToAddress(pk: Uint8Array, testnet = false): string {
  const hash = pubkeyToHash(pk);
  const words = bech32.toWords(hash);
  return bech32.encode(testnet ? PREFIX_TEST : PREFIX_MAIN, words);
}

export function isValidAddress(addr: string, testnet = false): boolean {
  try {
    const { prefix, words } = bech32.decode(addr);
    if (prefix !== (testnet ? PREFIX_TEST : PREFIX_MAIN)) return false;
    const data = bech32.fromWords(words);
    return data.length === 20;
  } catch {
    return false;
  }
}

export function addressToScriptPubkey(addr: string): Uint8Array {
  const { words } = bech32.decode(addr);
  const data = bech32.fromWords(words);
  const script = new Uint8Array(22);
  script[0] = 0x14;
  script.set(data, 1);
  script[21] = 0xac;
  return script;
}
