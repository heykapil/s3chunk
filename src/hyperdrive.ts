import { Hono } from "hono";
import postgres from "postgres";
import { Env } from "./env";

export const hyperdrive = new Hono<{Bindings: Env}>();

hyperdrive.post('/query', async (c) => {
    try {
        const { query, params } = await c.req.json<{ query: string; params?: any[] }>();

        if (!query) {
            return c.json({ error: 'The "query" field is required.' }, 400);
        }

        const result = await executeSanitizedQuery(c.env.HYPERDRIVE, query, params);

        if (!result.success) {
            return c.json({ error: result.error }, 500);
        }

        return c.json(result);

    } catch (e: any) {
        return c.json({ error: 'Invalid request body' }, 400);
    }
});

export async function executeSanitizedQuery(hyperdrive: Hyperdrive, query: string, params: any[] = []) {
  const sql = postgres(hyperdrive.connectionString, {
    // Recommended options for serverless environments like Cloudflare Workers
    max: 1,
    idle_timeout: 5,
    connect_timeout: 10,
  });
  try {
    const result = await sql.unsafe(query, params);
    return { success: true, results: result };
  } catch (e: any) {
    return { success: false, error: "Database query failed." };
  }
}
