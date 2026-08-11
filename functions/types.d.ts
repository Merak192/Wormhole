/**
 * Cloudflare Pages Functions type extensions
 */

// Extend Env type for KV binding
declare global {
  interface Env {
    WORM_HOLE: KVNamespace;
  }
}

export {};
