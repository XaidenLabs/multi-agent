import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";

export interface StoredObject {
  uri: string;
  contentHash: string;
  sizeBytes: number;
}

export interface PutObjectInput {
  tenantId: string;
  category: "evidence" | "defense" | "replay";
  objectId: string;
  bytes: Uint8Array;
  expectedHash: string;
}

export interface PrivateObjectStore {
  healthCheck(): Promise<void>;
  put(input: PutObjectInput): Promise<StoredObject>;
  get(uri: string, expectedHash: string): Promise<Uint8Array>;
  delete(uri: string): Promise<void>;
}

function sha256(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function safeSegment(value: string): string {
  if (!/^[A-Za-z0-9._:-]+$/.test(value)) throw new Error("Object storage key contains an unsafe segment");
  return value;
}

function verifyBytes(bytes: Uint8Array, expectedHash: string): void {
  if (sha256(bytes) !== expectedHash) throw new Error("Object content hash mismatch");
}

export class InMemoryPrivateObjectStore implements PrivateObjectStore {
  private readonly objects = new Map<string, Uint8Array>();

  async healthCheck(): Promise<void> {}

  async put(input: PutObjectInput): Promise<StoredObject> {
    verifyBytes(input.bytes, input.expectedHash);
    const uri = `memory-object://${safeSegment(input.tenantId)}/${input.category}/${safeSegment(input.objectId)}/${input.expectedHash.slice(7)}`;
    this.objects.set(uri, Uint8Array.from(input.bytes));
    return { uri, contentHash: input.expectedHash, sizeBytes: input.bytes.byteLength };
  }

  async get(uri: string, expectedHash: string): Promise<Uint8Array> {
    const bytes = this.objects.get(uri);
    if (!bytes) throw new Error("Object not found");
    verifyBytes(bytes, expectedHash);
    return Uint8Array.from(bytes);
  }

  async delete(uri: string): Promise<void> {
    this.objects.delete(uri);
  }
}

export class FileSystemPrivateObjectStore implements PrivateObjectStore {
  private readonly root: string;

  constructor(root: string) {
    if (!root.trim()) throw new Error("Object storage root is required");
    this.root = resolve(root);
  }

  async healthCheck(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await access(this.root, constants.R_OK | constants.W_OK);
  }

  async put(input: PutObjectInput): Promise<StoredObject> {
    verifyBytes(input.bytes, input.expectedHash);
    const relative = join(
      safeSegment(input.tenantId),
      input.category,
      safeSegment(input.objectId),
      `${input.expectedHash.slice(7)}.json`,
    );
    const target = this.resolveUri(`file-object://${relative}`);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const temporary = `${target}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, input.bytes, { mode: 0o600, flag: "wx" });
    try {
      await rename(temporary, target);
    } catch (error) {
      await rm(temporary, { force: true });
      throw error;
    }
    return { uri: `file-object://${relative}`, contentHash: input.expectedHash, sizeBytes: input.bytes.byteLength };
  }

  async get(uri: string, expectedHash: string): Promise<Uint8Array> {
    const bytes = await readFile(this.resolveUri(uri));
    verifyBytes(bytes, expectedHash);
    return bytes;
  }

  async delete(uri: string): Promise<void> {
    await rm(this.resolveUri(uri), { force: true });
  }

  private resolveUri(uri: string): string {
    if (!uri.startsWith("file-object://")) throw new Error("Unsupported object URI");
    const relative = uri.slice("file-object://".length);
    const target = resolve(this.root, relative);
    if (target !== this.root && !target.startsWith(`${this.root}${sep}`)) throw new Error("Object URI escaped its storage root");
    return target;
  }
}
