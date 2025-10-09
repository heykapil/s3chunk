import { AwsClient } from "aws4fetch";
import { XMLParser } from "fast-xml-parser";
import { Hono } from "hono";
import { Env } from "./env";
import { executeSanitizedQuery } from "./hyperdrive";
import { decryptSecret, getSha256, getSnowflakeGenerator } from "./jose";

type BucketConfig = {
  id: number;
  name: string;
  region: string;
  endpoint: string;
  accessKeyId: string;
  secretAccessKey: string;
  cdnUrl: string;
};

type Variables = {
  s3: AwsClient;
  bucketConfig: BucketConfig;
};

export const downloader = new Hono<{ Bindings: Env }>();


downloader.get('/download', async (c) => {
    const fileId = c.req.query('id');
    if (!fileId) {
        return c.json({ error: 'File ID is required' }, 400);
    }

    try {
        // 1. Fetch file metadata from the database using the fileId
        const fileResult = await c.env.DB.prepare(
            `SELECT key, bucket_id FROM files WHERE id = ? AND status = 'completed'`
        ).bind(fileId).first();
        // console.log(fileResult)
        if (!fileResult) {
            return c.json({ error: 'File not found or not available' }, 404);
        }

        const { key, bucket_id } = fileResult as { key: string; bucket_id: number };

        // 2. Fetch the bucket configuration using the bucket_id from the file record
        const bucketQuery = `SELECT * FROM s3_buckets WHERE id = ${bucket_id}`;
        const bucketResponse = await executeSanitizedQuery(c.env.HYPERDRIVE, bucketQuery);

        if (!bucketResponse.success || !bucketResponse.results || bucketResponse.results.length !== 1) {
            return c.json({ error: 'Associated bucket not found' }, 404);
        }

        const dbBucket = bucketResponse.results[0];
        const bucketConfig: BucketConfig = {
            id: dbBucket.id,
            name: dbBucket.name,
            region: dbBucket.region,
            endpoint: dbBucket.endpoint,
            accessKeyId: await decryptSecret(dbBucket.access_key_encrypted, c.env.API_KEY),
            secretAccessKey: await decryptSecret(dbBucket.secret_key_encrypted, c.env.API_KEY),
            cdnUrl: dbBucket.cdn_url || `${dbBucket.endpoint}/${dbBucket.name}`
        };

        // 3. Create a temporary S3 client for this request
        const s3 = new AwsClient({
            accessKeyId: bucketConfig.accessKeyId,
            secretAccessKey: bucketConfig.secretAccessKey,
            service: "s3",
            region: bucketConfig.region,
        });

        // 4. Generate and sign the download URL
        const url = new URL(`${bucketConfig.endpoint}/${bucketConfig.name}/${key}`);
        const signedRequest = await s3.sign(url, {
            method: 'GET',
            aws: { signQuery: true } // Creates a presigned URL
        });

        // 5. Redirect the client to the temporary, secure download link
        return c.redirect(signedRequest.url);

    } catch (err: any) {
        console.error("Download error:", err);
        return c.json({ error: 'Could not process download request' }, 500);
    }
});



export const files = new Hono<{ Bindings: Env, Variables: Variables }>()

files.use(async (c, next) => {
  const bucketId = parseInt(c.req.query("bucketId") as string);
  if (!bucketId || isNaN(bucketId) || bucketId < 0) {
    return c.json({ error: "bucketId is required" }, 400);
  }

  const query = `SELECT * FROM s3_buckets WHERE id = ${bucketId}`;
  const response = await executeSanitizedQuery(c.env.HYPERDRIVE, query)

  if(!response.success ||!response.results || response.results?.length !== 1){
    return c.json({ error: "bucket not found" }, 404);
  }
  // console.log('bucketConfig fetched from bucketId')
  const bucketConfig = {
    id: response.results[0].id,
    name: response.results[0].name,
    region: response.results[0].region,
    endpoint: response.results[0].endpoint,
    accessKeyId: response.results[0].access_key_encrypted,
    secretAccessKey: response.results[0].secret_key_encrypted,
    cdnUrl: response.results[0]?.cdn_url || response.results[0].endpoint + '/' + response.results[0].name
  }

  const decreyt_access_key_id = await decryptSecret(bucketConfig.accessKeyId, c.env.API_KEY)
  const decrypt_secret_access_key = await decryptSecret(bucketConfig.secretAccessKey, c.env.API_KEY)
  // console.log('decrypted access_key_id and secret_access_key')
  const s3 = new AwsClient({
    accessKeyId: decreyt_access_key_id,
    secretAccessKey: decrypt_secret_access_key,
    service: "s3",
    region: bucketConfig.region,
  });

  c.set('s3', s3);
  c.set('bucketConfig', bucketConfig);

  await next();
});

files.post('/upload', async (c) => {
  const s3 = c.get('s3');
  const bucketConfig = c.get('bucketConfig');
  const formData = await c.req.formData();
  const file = formData.get('file') as unknown as File;
  if (!file) return c.json({ error: 'No file provided' }, 400);
  const key = `uploads/${Date.now()}-${file.name}`
  // console.log('file found from formData')
  const buffer = await file.arrayBuffer();
  const url = new URL(`${bucketConfig.endpoint}/${bucketConfig.name}/${key}`);
  const fileid: string = getSnowflakeGenerator({});
  // console.log('generated fileId')
  try {
    const signedRequest = await s3.sign(url, {
      method: 'PUT',
      headers: {
        'Content-Type': file.type,
        'Content-Length': file.size.toString(),
        'x-amz-content-sha256': await getSha256(buffer),
      },
      body: buffer,
    });
    const response = await fetch(signedRequest);

    if (!response.ok) {
      await c.env.DB.prepare(
        `INSERT INTO files (id, key, file_name, size_bytes, content_type, bucket_name, bucket_id, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'failed')`
      ).bind(fileid, key, file.name, file.size, file.type, bucketConfig.name, bucketConfig.id).run();
      return c.json({ error: 'File upload failed' }, 500);
    }
    // console.log('uploaded file')
    await c.env.DB.prepare(
      `INSERT INTO files (id, key, file_name, size_bytes, content_type, bucket_name, bucket_id, status, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', CURRENT_TIMESTAMP)`
    ).bind(fileid, key, file.name, file.size, file.type, bucketConfig.name, bucketConfig.id).run();

    return c.json({ success: true, fileid, key, url: new URL(`${bucketConfig.cdnUrl}/${key}`) });
  } catch(err: any) {
    console.error(err)
    await c.env.DB.prepare(
      `INSERT INTO files (id, key, file_name, size_bytes, content_type, bucket_name, bucket_id, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'failed')`
    ).bind(fileid, key, file.name, file.size, file.type, bucketConfig.name, bucketConfig.id).run();
    return c.json({ success: false,error: 'File upload failed', message: err.message }, 500);
  }
})

// 1. Client asks for a URL to upload a file to.
files.post('/presign', async (c) => {
    const s3 = c.get('s3');
    const bucketConfig = c.get('bucketConfig');
    const { fileName, contentType } = await c.req.json();

    if (!fileName || !contentType) {
        return c.json({ error: 'fileName and contentType are required' }, 400);
    }

    const key = `uploads/${Date.now()}-${fileName}`;
    const fileId: string = getSnowflakeGenerator({});
    const url = new URL(`${bucketConfig.endpoint}/${bucketConfig.name}/${key}`);

    // Sign a PUT request. The client will use this URL to upload.
    // X-Amz-Expires sets the validity duration of the URL in seconds.
    url.searchParams.set('X-Amz-Expires', '360'); // 6 minutes
    const signedRequest = await s3.sign(url, {
        method: 'PUT',
        headers: { 'Content-Type': contentType },
        aws: { signQuery: true },
    });

    return c.json({
        success: true,
        uploadUrl: signedRequest.url,
        fileId, // Client must send this back in the /complete step
        key,
        finalUrl: `${bucketConfig.cdnUrl}/${key}`
    });
});

// 2. Client confirms the upload is done, and we write to the database.
files.post('/complete', async (c) => {
    const bucketConfig = c.get('bucketConfig');
    const { fileId, key, fileName, sizeBytes, contentType } = await c.req.json();

    if (!fileId || !key || !fileName || !sizeBytes || !contentType) {
        return c.json({ error: 'Missing required fields for completion' }, 400);
    }

    await c.env.DB.prepare(
        `INSERT INTO files (id, key, file_name, size_bytes, content_type, bucket_name, bucket_id, status, completed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', CURRENT_TIMESTAMP)`
    ).bind(fileId, key, fileName, sizeBytes, contentType, bucketConfig.name, bucketConfig.id).run();

    return c.json({ success: true, fileId });
});


// --- Multipart Presigned Upload ---

// 1. Initiate the multipart upload.
files.post('/multipart/initiate', async (c) => {
    const s3 = c.get('s3');
    const bucketConfig = c.get('bucketConfig');
    const { fileName, contentType } = await c.req.json();

    const key = `uploads/${Date.now()}-${fileName}`;
    const fileId: string = getSnowflakeGenerator({});
    const url = new URL(`${bucketConfig.endpoint}/${bucketConfig.name}/${key}?uploads`);

    const signedRequest = await s3.sign(url, {
        method: 'POST',
        headers: { 'Content-Type': contentType },
    });

    const response = await fetch(signedRequest);
    if (!response.ok) {
        return c.json({ error: 'Failed to initiate multipart upload' }, 500);
    }

    const xmlText = await response.text();
    const parser = new XMLParser();
    const result = parser.parse(xmlText);
    const uploadId = result.InitiateMultipartUploadResult.UploadId;

    // Store a pending record
    await c.env.DB.prepare(
        `INSERT INTO files (id, key, file_name, content_type, bucket_name, bucket_id, status)
         VALUES (?, ?, ?, ?, ?, ?, 'pending')`
    ).bind(fileId, key, fileName, contentType, bucketConfig.name, bucketConfig.id).run();

    return c.json({ success: true, fileId, key, uploadId });
});

// 2. Get a presigned URL for a specific chunk (part).
files.post('/multipart/presign', async (c) => {
    const s3 = c.get('s3');
    const bucketConfig = c.get('bucketConfig');
    const { key, uploadId, partNumber } = await c.req.json();

    if (!key || !uploadId || !partNumber) {
        return c.json({ error: 'key, uploadId, and partNumber are required' }, 400);
    }

    const url = new URL(`${bucketConfig.endpoint}/${bucketConfig.name}/${key}`);
    url.searchParams.set('uploadId', uploadId);
    url.searchParams.set('partNumber', partNumber);
    url.searchParams.set('X-Amz-Expires', '360'); // 6 minute expiry for the part URL

    const signedRequest = await s3.sign(url, { method: 'PUT', aws: { signQuery: true } });

    return c.json({ success: true, uploadUrl: signedRequest.url });
});

// 3. Finalize the multipart upload.
files.post('/multipart/complete', async (c) => {
    const s3 = c.get('s3');
    const bucketConfig = c.get('bucketConfig');
    const { fileId, key, uploadId, parts, sizeBytes } = await c.req.json();

    if (!fileId || !key || !uploadId || !parts || !Array.isArray(parts)) {
        return c.json({ error: 'key, uploadId, and an array of parts are required' }, 400);
    }

    // Construct the XML body required by the S3 CompleteMultipartUpload API
    const xmlBody = `<CompleteMultipartUpload>${
        parts.map(p => `<Part><PartNumber>${p.PartNumber}</PartNumber><ETag>${p.ETag}</ETag></Part>`).join('')
    }</CompleteMultipartUpload>`;

    const url = new URL(`${bucketConfig.endpoint}/${bucketConfig.name}/${key}?uploadId=${uploadId}`);
    const signedRequest = await s3.sign(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: xmlBody,
    });

    const response = await fetch(signedRequest);

    if (!response.ok) {
        console.error("Multipart completion failed:", await response.text());
        // You might want to add an abort logic here
        await c.env.DB.prepare(`UPDATE files SET status = 'failed' WHERE id = ?`).bind(fileId).run();
        return c.json({ error: 'Failed to complete multipart upload' }, 500);
    }

    // Update the database record to 'completed'
    await c.env.DB.prepare(
        `UPDATE files SET status = 'completed', completed_at = CURRENT_TIMESTAMP, size_bytes = ? WHERE id = ?`
    ).bind(sizeBytes, fileId).run();

    return c.json({ success: true, finalUrl: `${bucketConfig.cdnUrl}/${key}` });
});
