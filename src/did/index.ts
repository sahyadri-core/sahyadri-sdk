// @ts-nocheck
import { sha3 } from '../sha3';

export interface DidDocument {
  id: string;
  controller: string;
  publicKeyHex: string;
  created: number;
  services: Array<{ type: string; endpoint: string }>;
}

export function createDid(address: string, publicKeyHex: string): DidDocument {
  const did = `did:sahyadri:${address}`;
  return {
    id: did,
    controller: address,
    publicKeyHex,
    created: Math.floor(Date.now() / 1000),
    services: []
  };
}

export function didToHash(did: string): Uint8Array {
  return sha3(new TextEncoder().encode(did));
}

export function addService(
  doc: DidDocument,
  type: string,
  endpoint: string
): DidDocument {
  doc.services.push({ type, endpoint });
  return doc;
}
