// @ts-nocheck
export type Hash = Uint8Array;
export type PublicKey = Uint8Array;
export type SecretKey = Uint8Array;
export type Signature = Uint8Array;
export type Address = string;
export type TransactionId = string;

export interface KeyPair {
  publicKey: PublicKey;
  secretKey: SecretKey;
}

export interface RpcConfig {
  url?: string;
  timeout?: number;
}

export interface BalanceResult {
  address: Address;
  balance: string;
  nonce: number;
}

export interface SubmitTxResult {
  transactionId: TransactionId;
  accepted: boolean;
}
