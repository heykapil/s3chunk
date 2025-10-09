import type { D1Database, Hyperdrive, KVNamespace } from '@cloudflare/workers-types';

export type Env = {
  MY_KV: KVNamespace;
  DB: D1Database;
  HYPERDRIVE: Hyperdrive;
  API_KEY: string;
  SIGNING_PUBLIC_KEY: string;
};
