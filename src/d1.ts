import { Hono } from "hono";
import { Env } from "./env";

// --- Group for D1 Routes ---
export const d1 = new Hono<{ Bindings: Env }>();

/**
 * Execute a raw SQL query on the D1 database
 * POST /d1/query
 * Body: { "query": "SELECT * FROM users WHERE id = ?", "params": [1] }
 */
d1.post('/query', async (c) => {
  try {
    const { query, params } = await c.req.json<{ query: string; params?: any[] }>();

    if (!query) {
      return c.json({ error: 'The "query" field is required.' }, 400);
    }

    const stmt = c.env.DB.prepare(query);
    const boundStmt = params && Array.isArray(params) ? stmt.bind(...params) : stmt;

    let data;
    if (query.trim().toUpperCase().startsWith('SELECT')) {
        data = await boundStmt.all();
    } else {
        data = await boundStmt.run();
    }

    return c.json(data);
  } catch (e: any) {
    // Provide detailed error for easier debugging
    return c.json({ error: 'D1 query failed', details: e.message }, 500);
  }
});
