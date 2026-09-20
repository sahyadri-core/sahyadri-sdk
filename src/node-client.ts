// @ts-nocheck
// Sahyadri Node WebSocket Client - Pure JS

declare const WebSocket: any;

let WS: any;

// Browser ya Node dono ke liye
if (typeof globalThis !== 'undefined' && typeof globalThis.WebSocket !== 'undefined') {
  WS = globalThis.WebSocket;
} else {
  // Node.js ke liye
  try {
    WS = require('ws');
  } catch (e) {
    console.warn('WebSocket not available. Install: npm install ws');
  }
}

const WS_URL = 'ws://127.0.0.1:27110';

export class SahyadriClient {
  private ws: any = null;
  private requestId = 0;
  private pending = new Map<number, { resolve: any; reject: any }>();

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WS(WS_URL);
      
      this.ws.on('open', () => resolve());
      this.ws.on('error', (e: any) => reject(e));
      
      this.ws.on('message', (data: any) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.id && this.pending.has(msg.id)) {
            const { resolve, reject } = this.pending.get(msg.id)!;
            this.pending.delete(msg.id);
            if (msg.error) reject(new Error(msg.error.message));
            else resolve(msg.result);
          }
        } catch (e) {
          console.warn('WS message error:', e);
        }
      });
    });
  }

  async call(method: string, params: any = {}): Promise<any> {
    if (!this.ws) throw new Error('Not connected');
    
    const id = ++this.requestId;
    
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      
      this.ws.send(JSON.stringify({
        jsonrpc: '2.0',
        id,
        method,
        params,
      }));
      
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error('Timeout'));
        }
      }, 5000);
    });
  }

  async getBalance(address: string): Promise<number> {
    const result = await this.call('getBalanceByAddress', { address });
    return parseFloat(result?.balance || '0') / 1e8;
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Returns current virtual DAA score.
   * Used to compute FlashTx expiry.
   */
  async getDaaScore(): Promise<bigint> {
    const result = await this.call('getDaaScore', {});
    return BigInt(result?.daa_score ?? 0);
  }
}
