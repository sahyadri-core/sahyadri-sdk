// @ts-nocheck
/**
 * Sahyadri DID (Decentralized Identifier) Implementation
 * Based on CREST Model - Compatible with Sahyadri L1 Consensus
 * 
 * DID Format: did:sahyadri:{base58check-encoded-hash}
 */

import { keypair, sign, verify } from '../dilithium/index';
import { pubkeyToAddress } from '../address';
import { shake256Bytes } from "../sha3";

// ═══════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════

export interface CrestService {
  id: string;
  type: string;
  serviceEndpoint: string;
}

export interface CrestAuthentication {
  id: string;
  type: string;
  publicKeyHex: string;
}

export interface CrestDocument {
  context: string[];
  id: string;
  controller: string;
  csm_address: string;
  public_key_hex: string;
  version_id: number;
  active: boolean;
  created_at: string;
  updated_at?: string;
  deactivated_at?: string;
  services: CrestService[];
  authentication: CrestAuthentication[];
  proof?: CrestProof;
}

export interface CrestProof {
  type: string;
  created: string;
  verificationMethod: string;
  proofValue: string;
  challenge?: string;
  domain?: string;
}

export enum CrestPurpose {
  AUTHENTICATION = "authentication",
  KEY_AGREEMENT = "key-agreement",
  ASSERTION_METHOD = "assertion_method",
  CAPABILITY_INVOCATION = "capability_invocation",
  CAPABILITY_DELEGATION = "capability_delegation"
}

export enum CrestError {
  INVALID_FORMAT = "INVALID_DID_FORMAT",
  ALREADY_EXISTS = "ALREADY_EXISTS",
  NOT_FOUND = "NOT_FOUND",
  DEACTIVATED = "DEACTIVATED",
  INVALID_SIGNATURE = "INVALID_SIGNATURE",
  EXPIRED = "EXPIRED",
  VALIDATION_ERROR = "VALIDATION_ERROR"
}

export interface DidResolutionResult {
  didResolutionMetadata: { contentType: string; error?: string };
  didDocument: CrestDocument | null;
  didDocumentMetadata: { versionId: number; deactivated: boolean };
}

// ═══════════════════════════════════════════
// CONSTANTS & UTILITIES
// ═══════════════════════════════════════════

export const DID_PREFIX = "did:sahyadri:";
export const DID_METHOD = "sahyadri";

export function isValidDidFormat(did: string): boolean {
  return did.startsWith(DID_PREFIX) && did.length > DID_PREFIX.length + 10;
}

export function parseDid(did: string): { method: string; identifier: string } | null {
  if (!isValidDidFormat(did)) return null;
  const parts = did.split(":");
  if (parts.length !== 3) return null;
  return { method: parts[1], identifier: parts[2] };
}

export function generateDidIdentifier(publicKey: Uint8Array): string {
  const hash = shake256Bytes(publicKey, 32);
  return base58Encode(hash).slice(0, 32);
}

function base58Encode(bytes: Uint8Array): string {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = [0];
  
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  
  let result = "";
  for (let i = 0; i < digits.length; i++) result = ALPHABET[digits[i]] + result;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) result = "1" + result;
  return result;
}

// ═══════════════════════════════════════════
// CREST DOCUMENT BUILDER
// ═══════════════════════════════════════════

export class CrestBuilder {
  private doc: CrestDocument;

  constructor(did: string, csmAddress: string, publicKeyHex: string) {
    this.doc = {
      context: ["https://www.w3.org/ns/did/v1", "https://sahyadri.network/did/v1"],
      id: did,
      controller: did,
      csm_address: csmAddress,
      public_key_hex: publicKeyHex,
      version_id: 1,
      active: true,
      created_at: new Date().toISOString(),
      services: [],
      authentication: []
    };
  }

  static new(did: string, csmAddress: string, publicKeyHex: string): CrestBuilder {
    return new CrestBuilder(did, csmAddress, publicKeyHex);
  }

  addService(service: CrestService): this {
    if (!service.id.startsWith("#")) service.id = "#" + service.id;
    this.doc.services.push(service);
    return this;
  }

  addAuthentication(auth: CrestAuthentication): this {
    if (!auth.id.startsWith("#")) auth.id = "#" + auth.id;
    this.doc.authentication.push(auth);
    return this;
  }

  setController(controller: string): this {
    this.doc.controller = controller;
    return this;
  }

  setVersion(version: number): this {
    this.doc.version_id = version;
    return this;
  }

  build(): CrestDocument {
    return { ...this.doc };
  }
}

// ═══════════════════════════════════════════
// DID OPERATIONS
// ═══════════════════════════════════════════

export function signDidOperation(
  secretKey: Uint8Array,
  operation: "create" | "update" | "deactivate",
  csmAddress: string,
  timestamp?: number
): { signature: Uint8Array; message: string } {
  const ts = timestamp || Math.floor(Date.now() / 1000);
  const message = `did:${operation}:${csmAddress}:${ts}`;
  const signature = sign(secretKey, new TextEncoder().encode(message));
  return { signature, message };
}

export function verifyDidOperation(
  publicKey: Uint8Array,
  signature: Uint8Array,
  operation: "create" | "update" | "deactivate",
  csmAddress: string,
  timestamp: number,
  maxAgeSeconds: number = 300
): boolean {
  const now = Math.floor(Date.now() / 1000);
  if (now - timestamp > maxAgeSeconds || timestamp > now) return false;
  const message = `did:${operation}:${csmAddress}:${timestamp}`;
  return verify(publicKey, signature, new TextEncoder().encode(message));
}

// ═══════════════════════════════════════════
// DID RESOLUTION
// ═══════════════════════════════════════════

export function resolveDidLocally(
  did: string,
  store: Map<string, CrestDocument>
): DidResolutionResult {
  if (!isValidDidFormat(did)) {
    return {
      didResolutionMetadata: { contentType: "application/did+json", error: "invalidDid" },
      didDocument: null,
      didDocumentMetadata: { versionId: 0, deactivated: false }
    };
  }
  
  const doc = store.get(did);
  if (!doc) {
    return {
      didResolutionMetadata: { contentType: "application/did+json", error: "notFound" },
      didDocument: null,
      didDocumentMetadata: { versionId: 0, deactivated: false }
    };
  }
  
  return {
    didResolutionMetadata: { contentType: "application/did+json" },
    didDocument: doc,
    didDocumentMetadata: { versionId: doc.version_id, deactivated: !doc.active }
  };
}

// ═══════════════════════════════════════════
// SERVICE HELPERS
// ═══════════════════════════════════════════

export function createDidCommService(endpoint: string, id: string = "#didcomm"): CrestService {
  return { id, type: "DIDCommMessaging", serviceEndpoint: endpoint };
}

export function createLinkedDomainsService(origin: string, id: string = "#domains"): CrestService {
  return { id, type: "LinkedDomains", serviceEndpoint: origin };
}
