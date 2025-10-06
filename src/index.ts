import { S3Client, UploadPartCommand } from '@aws-sdk/client-s3';
import { serve } from '@hono/node-server';
import 'dotenv/config';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger'; // ← Logger middleware
import { compactDecrypt, CompactEncrypt } from 'jose';
import { decrypt, verify } from 'paseto-ts/v4';

interface Env {
  PASETO_SECRET_KEY: string
  PASETO_PUBLIC_KEY: string
  PASETO_LOCAL_KEY: string
  ENCRYPTION_KEY: string
  NODE_ENV?: string
}

type Variables = {}

// Verify a public (v4.public) PASETO token
async function verifyPasetoToken(
  token: string,
  key?: string
): Promise<any | null> {
  try {
    const full = `v4.public.${token}`
    const publicKey = key ?? process.env.PASETO_PUBLIC_KEY!
    if(!publicKey){
      console.error('env vars are not setup correctly')
    }
    const { payload } = verify(publicKey, full)
    return payload
  } catch (e) {
    console.error('Verify Error:', e)
    return null
  }
}

// Decrypt a local (v4.local) PASETO token
async function decryptToken(token: string): Promise<any | null> {
  try {
    const full = `v4.local.${token}`
    const localKey = process.env.PASETO_LOCAL_KEY!
    if(!localKey){
      console.error('env vars are not setup correctly')
    }
    const { payload } = decrypt(localKey, full)
    return payload
  } catch (e) {
    console.error('Decrypt Error:', e)
    return null
  }
}


const masterKey = Buffer.from(process.env.ENCRYPTION_KEY!, 'base64');
if (masterKey.length !== 32) {
  throw new Error('Invalid ENCRYPTION_KEY length. Must be 32 bytes (256 bits) for A256GCM.');
}

const encryptionAlgorithm = 'A256GCM'; // AES-256-GCM is a highly secure and efficient standard.

/**
 * Encrypts a plaintext string using symmetric encryption (AES-256-GCM).
 * @param plaintext The secret string to encrypt (e.g., an S3 access key).
 * @returns A JWE string in Compact Serialization format.
 */
async function encryptSecret(plaintext: string): Promise<string> {
  const jwe = await new CompactEncrypt(new TextEncoder().encode(plaintext))
    .setProtectedHeader({
      alg: 'dir', // 'dir' stands for "Direct Encryption" with a shared symmetric key.
      enc: encryptionAlgorithm,
    })
    .encrypt(masterKey); // Encrypt using the single master key.

  return jwe;
}

/**
 * Decrypts a JWE string that was encrypted with the master key.
 * @param jwe The JWE string from the database.
 * @returns The original plaintext secret.
 */
async function decryptSecret(jwe: string): Promise<string> {
  try {
    const { plaintext } = await compactDecrypt(jwe, masterKey);
    return new TextDecoder().decode(plaintext);
  } catch (error) {
    console.error("Decryption failed:", error);
    // This typically means the master key is wrong or the data is corrupted.
    throw new Error("Failed to decrypt secret.");
  }
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// 1) Log every request/response (using console.log under the hood)
app.use('*', logger((msg, ...rest) => {
  console.log(msg, ...rest)
}))

// 2) Enable CORS
app.use('*', cors())

// Preflight handler
app.options('/upload', (c) => {
  return c.text('OK', 200, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-access-token',
  })
})

app.post('/upload', async (c) => {
  console.log('→ Handling POST /upload')

  const token = c.req.header('x-access-token')
  if (!token) {
    console.error('Missing x-access-token header')
    return c.json({ error: 'Missing access token' }, 401)
  }

  const verified = await verifyPasetoToken(token)
  if (!verified) {
    console.error('Invalid PASETO token')
    return c.json({ error: 'Invalid token' }, 401)
  }

  const form = await c.req.formData()
  const uploadId = form.get('uploadId')?.toString()
  const key = form.get('key')?.toString()
  const partNum = Number(form.get('partNumber'))
  const chunk = form.get('chunk')
  const s3config = form.get('s3config')?.toString()

  if (!uploadId || !key || !partNum || !chunk || !s3config) {
    console.error('Missing required form fields', { uploadId, key, partNum, chunk, s3config })
    return c.json({ error: 'Missing required fields' }, 400)
  }

  const bucketConfig = await decryptToken(s3config)
  if (!bucketConfig) {
    console.error('Invalid bucket configuration')
    return c.json({ error: 'Invalid bucket configuration' }, 400)
  }

  if (!(chunk instanceof Blob)) {
    console.error('Chunk is not a Blob')
    return c.json({ error: 'Invalid chunk type' }, 400)
  }
  const buffer = new Uint8Array(await chunk.arrayBuffer())
  const access_key_decrypted = await decryptSecret(bucketConfig.accessKey)
  const secret_key_decrypted = await decryptSecret(bucketConfig.secretKey)
  if(!access_key_decrypted || !secret_key_decrypted){
    console.error('Invalid access key or secret key')
    return c.json({ error: 'Invalid access key or secret key' }, 400)
  }
  const s3 = new S3Client({
    region: bucketConfig.region,
    endpoint: bucketConfig.endpoint,
    credentials: {
      accessKeyId: access_key_decrypted,
      secretAccessKey: secret_key_decrypted,
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

    console.info('Part uploaded', { key, partNum, ETag })
    return c.json({
      success: true,
      ETag: ETag.replace(/"/g, ''),
      cdnUrl: bucketConfig.cdnUrl ? `${bucketConfig.cdnUrl}/${key}` : undefined,
    })
  } catch (e: any) {
    console.error('Upload failed', e)
    return c.json({ error: 'Upload failed', details: e.message }, 500)
  }
})

app.get('/', (c) => c.text('OK'))
app.get('/health', (c) => c.text('OK'))

// Start server
serve({
  fetch: app.fetch,
  port: Number(process.env.PORT) || 8080,
  hostname: '0.0.0.0',
})

console.log(`Running on port ${Number(process.env.PORT) || 8080}`)
