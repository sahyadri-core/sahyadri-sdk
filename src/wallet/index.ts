// @ts-nocheck
import { keypair, sign } from '../dilithium/index';
import { pubkeyToAddress } from '../address';
import { RpcClient } from '../rpc/client';

export class Wallet {
  private rpc: RpcClient;
  public publicKey: Uint8Array = new Uint8Array(1952);
  public secretKey: Uint8Array = new Uint8Array(4032);
  public address: string = '';
  public balance: number = 0;
  public nonce: number = 0;

  constructor(rpcUrl: string = 'ws://127.0.0.1:27110') {
    this.rpc = new RpcClient(rpcUrl);
  }

  async connect(): Promise<void> {
    await this.rpc.connect();
  }

  create(): void {
    const { publicKey, secretKey } = keypair();
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.address = pubkeyToAddress(publicKey);
  }

  async getBalance(): Promise<number> {
    this.balance = await this.rpc.getBalance(this.address);
    return this.balance;
  }

  async send(to: string, amountKana: number): Promise<string> {
    const payload = Buffer.from(this.publicKey).toString('hex');
    const txData = `${this.address}:${to}:${amountKana}:${this.nonce}`;
    // Using new sign() from @noble/post-quantum
    const signature = sign(this.secretKey, new TextEncoder().encode(txData));
    const sigHex = Buffer.from(signature).toString('hex');

    const tx = {
      sender: this.address,
      receiver: to,
      amount: amountKana,
      fee: 1000,
      nonce: this.nonce,
      payload,
      signature: sigHex
    };

    const txId = await this.rpc.submitTransaction(tx);
    this.nonce++;
    return txId;
  }
}
