import { S3Client, UploadPartCommand } from '@aws-sdk/client-s3'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { decryptTokenV4, verifyPasetoToken } from './paseto'
const app = new Hono()

// 1. Enable CORS (preflight + actual) and log OPTIONS hits
app.use(
  '/upload',
  cors({
    origin: '*',
    allowMethods: ['POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'x-access-token'],
    exposeHeaders: ['ETag'],
  })
)
app.options('/upload', (c) => {
  // console.log('[OPTIONS] /upload – sending CORS headers')
  return c.text('', 204)
})

app.post('/upload', async (c) => {
  // console.log('[POST] /upload – start processing')
  // CORS headers for actual response
  c.header('Access-Control-Allow-Origin', '*')
  c.header('Access-Control-Expose-Headers', 'ETag')

  // 2. Auth
  const token = c.req.header('x-access-token')
  // console.log('[Auth] Received token:', token)
  if (!token) {
    // console.warn('[Auth] Missing access token')
    return c.json({ error: 'Missing access token' }, 401)
  }

  let verified: boolean
  try {
    verified = await verifyPasetoToken(c.env as any, token)
    // console.log('[Auth] Token verification result:', verified)
    if (!verified) {
      // console.warn('[Auth] Invalid access token')
      return c.json({ error: 'Invalid token' }, 401)
    }
  } catch (err: any) {
    // console.error('[Auth] Error verifying token:', err)
    return c.json({ error: 'Token verification failed', details: err.message }, 500)
  }

  // 3. Parse & validate form data
  let body: any
  try {
    body = await c.req.parseBody()
    // console.log('[Parse] form data parsed:', body)
  } catch (err: any) {
    // console.error('[Parse] Failed to parse body:', err)
    return c.json({ error: 'Invalid form data', details: err.message }, 400)
  }

  const { uploadId, key, partNumber, chunk, s3config } = body
  if (!uploadId || !key || !partNumber || !chunk || !s3config) {
    // console.warn('[Validate] Missing one of required fields:', {
    //   uploadId,
    //   key,
    //   partNumber,
    //   chunk: !!chunk,
    //   s3config,
    // })
    return c.json({ error: 'Missing required fields' }, 400)
  }

  // 4. Decrypt bucket config
  let bucketConfig: any
  try {
    bucketConfig = await decryptTokenV4(c.env as any, s3config)
  } catch (err: any) {
    return c.json({ error: 'Invalid bucket configuration' }, 400)
  }


  let etag;
  try {
    const buffer = new Uint8Array(await (chunk as any).arrayBuffer())

    const client = new S3Client({
      region: bucketConfig.region || 'auto',
      endpoint: bucketConfig.endpoint,
      credentials: {
        accessKeyId: bucketConfig.accessKey,
        secretAccessKey: bucketConfig.secretKey,
      },
      forcePathStyle: true,
    });
    const command = new UploadPartCommand({
      Bucket: bucketConfig.name,
      Key: key,
      UploadId: uploadId,
      PartNumber: partNumber,
      Body: buffer,
    });

    const response = await client.send(command);


    etag = response?.ETag?.replace(/"/g, '');

    if (!etag) {
      return c.json({ error: 'Missing ETag in upload response' }, 500)
    }
  } catch (err: any) {
    return c.json({ error: 'Upload failed', details: err.message }, 500)
  }
  return c.json(
    {
      success: true,
      ETag: etag,
      cdnUrl: bucketConfig.cdnUrl ? `${bucketConfig.cdnUrl}/${key}` : undefined,
    },
    200
  )
})

export default app
