// @ts-nocheck
// Local storage for wallet data (browser/Node.js compatible)
export class Storage {
  private store: Map<string, string> = new Map();

  set(key: string, value: any): void {
    this.store.set(key, JSON.stringify(value));
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(key, JSON.stringify(value));
    }
  }

  get<T>(key: string): T | null {
    const value = this.store.get(key) || 
      (typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null);
    return value ? JSON.parse(value) as T : null;
  }

  remove(key: string): void {
    this.store.delete(key);
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(key);
    }
  }

  clear(): void {
    this.store.clear();
    if (typeof localStorage !== 'undefined') {
      localStorage.clear();
    }
  }
}
