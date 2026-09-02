// @ts-nocheck
import { sha3 } from './sha3';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

// Node ka polymod - EXACT port from bech32.rs
function polymod(values: number[]): number {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    
    if (c0 & 0x01n) c ^= 0x98f2bc8e61n;
    if (c0 & 0x02n) c ^= 0x79b76d99e2n;
    if (c0 & 0x04n) c ^= 0xf33e5fb3c4n;
    if (c0 & 0x08n) c ^= 0xae2eabe2a8n;
    if (c0 & 0x10n) c ^= 0x1e4f43e470n;
  }
  return Number(c ^ 0x2bc830a3n);
}

// Node ka checksum - prefix.chain([0]).chain(payload).chain([0;8])
function checksum(payload: number[], prefix: string): number {
  const prefixBytes: number[] = [];
  for (const c of prefix) prefixBytes.push(c.charCodeAt(0) & 0x1f);
  
  const values: number[] = [
    ...prefixBytes, 0,
    ...payload,
    0, 0, 0, 0, 0, 0, 0, 0,
  ];
  
  return polymod(values);
}

// Node ka conv8to5
function conv8to5(payload: number[]): number[] {
  const padding = payload.length % 5 === 0 ? 0 : 1;
  const fiveBit: number[] = new Array(Math.floor(payload.length * 8 / 5) + padding).fill(0);
  let currentIdx = 0;
  let buff = 0;
  let bits = 0;
  
  for (const c of payload) {
    buff = (buff << 8) | c;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      fiveBit[currentIdx] = (buff >> bits) & 0x1f;
      buff &= (1 << bits) - 1;
      currentIdx++;
    }
  }
  if (bits > 0) {
    fiveBit[currentIdx] = (buff << (5 - bits)) & 0x1f;
  }
  return fiveBit;
}

function pubkeyToHash(pk: Uint8Array): Uint8Array {
  return sha3(pk).slice(0, 20);
}

export function pubkeyToAddress(pk: Uint8Array): string {
  const hash = pubkeyToHash(pk);
  const payloadBytes = [129, ...Array.from(hash)]; // Version 129 + hash
  const fiveBitPayload = conv8to5(payloadBytes);
  const prefix = 'csm';
  
  const chk = checksum(fiveBitPayload, prefix);
  
  // Checksum (u64) to 5-bit: last 5 bytes (40 bits) = 8 groups
  const chkFiveBit: number[] = [];
  for (let i = 7; i >= 0; i--) {
    chkFiveBit.push(Number((BigInt(chk) >> BigInt(5 * i)) & 0x1fn));
  }
  
  let result = prefix + '1';
  for (const d of fiveBitPayload) result += CHARSET[d];
  for (const d of chkFiveBit) result += CHARSET[d];
  
  return result;
}

export function isValidAddress(addr: string): boolean {
  return addr.startsWith('csm1');
}
