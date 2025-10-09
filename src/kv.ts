import { Hono } from "hono";
import { Env } from "./env";

// --- Group for KV Routes ---
export const kv = new Hono<{ Bindings: Env }>();

/**
 * 1. Add a key-value pair
 * POST /kv/add
 * Body: { "key": "some-key", "value": "some-value" }
 */
kv.post('/add', async (c) => {
  try {
    const { key, value } = await c.req.json<{ key: string; value: string }>();
    if (!key || value === undefined) {
      return c.json({ error: 'Key and value are required' }, 400);
    }
    await c.env.MY_KV.put(key, value);
    return c.json({ success: true, message: `Successfully added key: ${key}` });
  } catch (e: any) {
    return c.json({ error: 'Failed to add value', details: e.message }, 500);
  }
});

/**
 * 2. Edit a key-value pair
 * PUT /kv/edit
 * Body: { "key": "some-key", "value": "new-value" }
 */
kv.put('/edit', async (c) => {
  try {
    const { key, value } = await c.req.json<{ key: string; value: string }>();
    if (!key || value === undefined) {
      return c.json({ error: 'Key and value are required' }, 400);
    }
    await c.env.MY_KV.put(key, value);
    return c.json({ success: true, message: `Successfully edited key: ${key}` });
  } catch (e: any) {
    return c.json({ error: 'Failed to edit value', details: e.message }, 500);
  }
});

/**
 * 3. List keys or get a specific key
 * GET /kv/list
 * GET /kv/list?key=some-key
 */
kv.get('/list', async (c) => {
  const key = c.req.query('key');

  // If a specific key is requested
  if (key) {
    const value = await c.env.MY_KV.get(key);
    if (value === null) {
      return c.json({ error: 'Key not found' }, 404);
    }
    return c.json({ [key]: value });
  }
  const list = await c.env.MY_KV.list();
  return c.json(list.keys);
});

/**
 * 4. Delete a key-value pair
 * DELETE /kv/delete?key=some-key
 */
kv.delete('/delete', async (c) => {
  const key = c.req.query('key');
  if (!key) {
    return c.json({ error: 'A "key" query parameter is required' }, 400);
  }
  await c.env.MY_KV.delete(key);
  return c.json({ success: true, message: `Successfully deleted key: ${key}` });
});
