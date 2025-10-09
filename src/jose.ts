import { compactDecrypt, importJWK, jwtVerify } from "jose";

export async function getSha256(body: ArrayBuffer | string): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', typeof body === 'string' ? new TextEncoder().encode(body) : body);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export async function decryptSecret(encrypted: string, key: string): Promise<string> {
  const masterKey = base64ToUint8Array(key);
  if (masterKey.length !== 32) {
      throw new Error('Decoded ENCRYPTION_KEY is not 32 bytes long!');
  }
  const { plaintext } = await compactDecrypt(encrypted, masterKey);
  return new TextDecoder().decode(plaintext);
}

function parseJWK(envVar?: string) {
  if (!envVar) throw new Error("❌ Missing JWK key in environment variables.");
  try {
    return JSON.parse(envVar); // Convert string to JSON object
  } catch (error) {
    console.error("❌ Invalid JSON in environment variable:", envVar, error);
    throw new Error("❌ Failed to parse JWK. Check your .env formatting.");
  }
}

export async function verifyJWT(token: string, key: string) {
  try {
    const jwk = parseJWK(key)
    const publicKey = await importJWK(jwk, "EdDSA")
    const { payload } = await jwtVerify(token, publicKey);
    return payload;
  } catch(error) {
    console.error("❌ Failed to verify JWT:", error);
    throw new Error("❌ Failed to verify JWT.");
  }
}


// A custom epoch (February 5, 2025) to make generated IDs smaller and more manageable.
const EPOCH = 1738693800000n;

// Define how many bits to allocate for each part of the ID.
// Total bits = 1 (sign) + 41 (timestamp) + 5 (datacenter) + 5 (worker) + 12 (sequence) = 64
const WORKER_ID_BITS = 5n;
const DATACENTER_ID_BITS = 5n;
const SEQUENCE_BITS = 12n;

// Calculate the maximum value for each part based on its bit allocation.
const MAX_WORKER_ID = -1n ^ (-1n << WORKER_ID_BITS);
const MAX_DATACENTER_ID = -1n ^ (-1n << DATACENTER_ID_BITS);

// Calculate the bit shifts required to assemble the final ID.
const WORKER_ID_SHIFT = SEQUENCE_BITS;
const DATACENTER_ID_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS;
const TIMESTAMP_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS + DATACENTER_ID_BITS;

export class SnowflakeGenerator {
  private sequence = 0n;
  private lastTimestamp = -1n;
  private readonly workerId: bigint;
  private readonly datacenterId: bigint;

  /**
   * Creates a new Snowflake ID generator.
   * @param workerId A unique ID for the worker instance (0-31).
   * @param datacenterId A unique ID for the datacenter/region (0-31).
   */
  constructor(workerId: number, datacenterId: number) {
    this.workerId = BigInt(workerId);
    this.datacenterId = BigInt(datacenterId);

    if (this.workerId < 0n || this.workerId > MAX_WORKER_ID) {
      throw new Error(`Worker ID must be between 0 and ${MAX_WORKER_ID}`);
    }
    if (this.datacenterId < 0n || this.datacenterId > MAX_DATACENTER_ID) {
      throw new Error(`Datacenter ID must be between 0 and ${MAX_DATACENTER_ID}`);
    }
  }

  /**
   * Waits for the next millisecond.
   * @param currentTimestamp The timestamp to wait beyond.
   */
  private tilNextMillis(currentTimestamp: bigint): bigint {
    let timestamp = BigInt(Date.now());
    while (timestamp <= currentTimestamp) {
      timestamp = BigInt(Date.now());
    }
    return timestamp;
  }

  /**
   * Generates the next unique, time-sortable 64-bit Snowflake ID.
   * @returns A new Snowflake ID as a BigInt.
   */
  public nextId(): bigint {
    let timestamp = BigInt(Date.now());

    // Check for clock skew. If the clock has moved backwards, throw an error.
    if (timestamp < this.lastTimestamp) {
      throw new Error("Clock moved backwards. Refusing to generate id.");
    }

    if (this.lastTimestamp === timestamp) {
      // We are in the same millisecond; increment the sequence.
      this.sequence = (this.sequence + 1n) & (-1n ^ (-1n << SEQUENCE_BITS));
      if (this.sequence === 0n) {
        // Sequence has overflowed (4096 IDs in one ms), wait for the next millisecond.
        timestamp = this.tilNextMillis(this.lastTimestamp);
      }
    } else {
      // New millisecond, reset the sequence.
      this.sequence = 0n;
    }

    this.lastTimestamp = timestamp;

    // Assemble the 64-bit ID using bitwise operations.
    return (
      ((timestamp - EPOCH) << TIMESTAMP_SHIFT) |
      (this.datacenterId << DATACENTER_ID_SHIFT) |
      (this.workerId << WORKER_ID_SHIFT) |
      this.sequence
    );
  }
}

export function getSnowflakeGenerator({workerId = 1, datacenterId = 1} : {workerId?: number, datacenterId?: number}) {
  const  snowflake = new SnowflakeGenerator(workerId, datacenterId)
  return snowflake.nextId().toString();
}
