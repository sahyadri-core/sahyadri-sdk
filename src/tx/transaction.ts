// @ts-nocheck
// Sahyadri Account Transaction
export interface AccountTransaction {
  sender: string;
  receiver: string;
  amount: number; // in Kana
  fee: number;    // in Kana
  nonce: number;
  payload: string;
  signature: string;
}

export function createTransaction(
  sender: string,
  receiver: string,
  amountKana: number,
  nonce: number,
  publicKeyHex: string
): AccountTransaction {
  const fee = 1000; // 0.00001 CSM
  return {
    sender,
    receiver,
    amount: amountKana,
    fee,
    nonce,
    payload: publicKeyHex,
    signature: ''
  };
}
