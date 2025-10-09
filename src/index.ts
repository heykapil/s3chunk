import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { downloader, files } from './aws4fetch';
import { d1 } from './d1';
import { Env } from './env';
import { hyperdrive } from './hyperdrive';
import { verifyJWT } from './jose';
import { kv } from './kv';

const app = new Hono<{ Bindings: Env }>();

const corsRegex = /^https?:\/\/(.+\.kapil\.app|kapil\.app|localhost:\d+)$/;

app.use('*', cors({
  origin: (origin) => (corsRegex.test(origin) ? origin : undefined),
}));

app.use('*', async (c, next) => {
  const accessToken = c.req.header('x-access-token');
  if (!accessToken) {
    return c.json({ error: 'Unauthorized' }, 401);
  } else {
    try{
      await verifyJWT(accessToken, c.env.SIGNING_PUBLIC_KEY)
    } catch(error){
      console.error(error);
      return c.json({ error: 'Unauthorized' }, 401);
    }
  }
  await next()
});

app.route('/kv', kv);
app.route('/d1', d1);
app.route('/hyperdrive', hyperdrive);
app.route('/files', files)
app.route('/file', downloader)

app.get('/', (c) => {
  return c.text('API worker is running!');
});

export default app;
