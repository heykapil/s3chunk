import { S3Client, UploadPartCommand } from '@aws-sdk/client-s3'
import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { decrypt, verify } from 'paseto-ts/v4'

interface Env {
  PASETO_SECRET_KEY: string
  PASETO_PUBLIC_KEY: string
  PASETO_LOCAL_KEY: string
  NODE_ENV?: string
}

// interface SignOption {
//   addExp?: boolean
//   footer?: string
// }

// interface BucketConfig {
//   name: string
//   accessKey: string
//   secretKey: string
//   region: string
//   endpoint: string
//   availableCapacity?: number
//   private?: boolean
//   cdnUrl?: string
//   provider?: string
// }


// const DefaultSignOption: SignOption = {
//   addExp: true,
//   footer: 'kapil.app',
// }

type Variables = {}


// Helper to strip prefixes
// const stripPrefix = (token: string, prefix: string) =>
//   token.startsWith(prefix) ? token.slice(prefix.length) : token

// async function signPasetoToken(
//   env: Env,
//   payload: Payload,
//   options: SignOption = DefaultSignOption,
//   key?: string
// ): Promise<string | null> {
//   try {
//     const token =  sign(key ?? env.PASETO_SECRET_KEY, payload, options)
//     return stripPrefix(token, 'v4.public.')
//   } catch (e) {
//     console.error('Sign Error:', e)
//     return null
//   }
// }

async function verifyPasetoToken(
  env: Env,
  token: string,
  key?: string
): Promise<any | null> {
  try {
    const full = `v4.public.${token}`
    const { payload } = verify(key ?? env.PASETO_PUBLIC_KEY, full)
    return payload
  } catch (e) {
    console.error('Verify Error:', e)
    return null
  }
}

// async function encryptToken(
//   env: Env,
//   payload: Payload,
//   options: SignOption = DefaultSignOption
// ): Promise<string | null> {
//   try {
//     const token = encrypt(env.PASETO_LOCAL_KEY, payload, options)
//     return stripPrefix(token, 'v4.local.')
//   } catch (e) {
//     console.error('Encrypt Error:', e)
//     return null
//   }
// }

async function decryptToken(
  env: Env,
  token: string
): Promise<any | null> {
  try {
    const full = `v4.local.${token}`
    const { payload } = decrypt(env.PASETO_LOCAL_KEY, full)
    return payload
  } catch (e) {
    console.error('Decrypt Error:', e)
    return null
  }
}

const app = new Hono<{ Bindings: Env, Variables: Variables }>()
app.use('*', cors())
app.options('/upload', (c) => {
  return c.text('OK',  200, {
    'Access-Control-Allow-Origin': '*', // or your specific origin
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-access-token'
  })
})
app.post('/upload', async (c) => {
  const token = c.req.header('x-access-token')
  if (!token) return c.json({ error: 'Missing access token' }, 401)

  const verified = await verifyPasetoToken(c.env, token)
  if (!verified) return c.json({ error: 'Invalid token' }, 401)

  const form = await c.req.formData()
  const uploadId = form.get('uploadId')?.toString()
  const key = form.get('key')?.toString()
  const partNum = Number(form.get('partNumber'))
  const chunk = form.get('chunk')
  const s3config = form.get('s3config')?.toString()

  if (!uploadId || !key || !partNum || !chunk || !s3config) {
    return c.json({ error: 'Missing required fields' }, 400)
  }

  const bucketConfig = await decryptToken(c.env, s3config)
  if (!bucketConfig) {
    return c.json({ error: 'Invalid bucket configuration' }, 400)
  }

  if (!(chunk instanceof Blob)) {
    return c.json({ error: 'Invalid chunk type' }, 400)
  }
  const buffer = new Uint8Array(await chunk.arrayBuffer())

  const s3 = new S3Client({
    region: bucketConfig.region,
    endpoint: bucketConfig.endpoint,
    credentials: {
      accessKeyId: bucketConfig.accessKey,
      secretAccessKey: bucketConfig.secretKey,
    },
    forcePathStyle: true,
  })

  try {
    const { ETag } = await s3.send(
      new UploadPartCommand({
        Bucket: bucketConfig.name,
        Key: key,
        UploadId: uploadId,
        PartNumber: partNum,
        Body: buffer,
      })
    )
    if (!ETag) throw new Error('No ETag returned')
    return c.json({
      success: true,
      ETag: ETag.replace(/"/g, ''),
      cdnUrl: bucketConfig.cdnUrl ? `${bucketConfig.cdnUrl}/${key}` : undefined,
    })
  } catch (e: any) {
    console.error('Upload error:', e)
    return c.json(
      { error: 'Upload failed', details: e.message },
      500
    )
  }
})

app.get('/', (c) => c.text('OK'))
app.get('/health', (c) => c.text('OK'))

export default app

serve({
  fetch: app.fetch,
  port: Number(process.env.PORT) || 8080,
  hostname: '0.0.0.0' // 👈 This is the critical missing piece
})

console.log(`Running on port ${Number(process.env.PORT) || 8080}`)
