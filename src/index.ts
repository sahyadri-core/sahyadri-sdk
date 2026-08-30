// @ts-nocheck
/**
 * @sahyadrinet/web3.js - Sahyadri L1 Blockchain SDK
 * Post-Quantum Secure Web3 Library
 */

// Core Crypto (ML-DSA-65 / Dilithium3)
export { keypair, sign, verify } from './dilithium/index';

// Address Generation (CSM32 Bech32)
export { pubkeyToAddress } from './address';

// Decentralized Identifiers (DID + CREST Model)
export {
  // Types
  CrestDocument,
  CrestService,
  CrestAuthentication,
  CrestProof,
  DidResolutionResult,
  CrestError,
  CrestPurpose,
  
  // DID Utilities
  isValidDidFormat,
  parseDid,
  generateDidIdentifier,
  DID_PREFIX,
  DID_METHOD,
  
  // CREST Builder
  CrestBuilder,
  
  // DID Operations
  signDidOperation,
  verifyDidOperation,
  resolveDidLocally,
  
  // Service Helpers
  createDidCommService,
  createLinkedDomainsService
} from './did/index';

// Wallet
export { Wallet } from './wallet/index';

// Hash Functions
export { shake256Bytes, shake256Digest, sha3 } from './sha3';
