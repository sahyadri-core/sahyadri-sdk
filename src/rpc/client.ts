// @ts-nocheck
// Sahyadri RPC Client - WebSocket connection to node
export class RpcClient {
  private url: string;
  private ws: WebSocket | null = null;
  private connected = false;

  constructor(url: string = 'ws://127.0.0.1:27110') {
    this.url = url;
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.onopen = () => { this.connected = true; resolve(); };
      this.ws.onerror = (e) => reject(e);
    });
  }

  isConnected(): boolean { return this.connected; }

  async call(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.ws || !this.connected) { reject('Not connected'); return; }
      const id = Date.now();
      const handler = (e: MessageEvent) => {
        const data = JSON.parse(e.data);
        if (data.id === id) {
          this.ws!.removeEventListener('message', handler);
          resolve(data.result || data);
        }
      };
      this.ws.addEventListener('message', handler);
      this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
  }

  async getBalance(address: string): Promise<number> {
    const result = await this.call('getBalanceByAddress', { address });
    return result?.balance || 0;
  }

  async submitTransaction(tx: any): Promise<string> {
    const result = await this.call('submitAccountTransaction', tx);
    return result?.transactionId || '';
  }
}
