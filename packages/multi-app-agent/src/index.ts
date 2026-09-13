import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export type IncidentSeverity = "medium" | "high" | "critical";
export type AppName = "github" | "slack" | "notion";

export interface SanitizedIncident {
  receiptId: string;
  attackClass: string;
  severity: IncidentSeverity;
  summary: string;
  evidenceHash: `sha256:${string}`;
  occurredAt: string;
}

export interface AppActionResult {
  externalId: string;
  url?: string;
}

export interface IncidentApp {
  name: AppName;
  execute(incident: SanitizedIncident, idempotencyKey: string): Promise<AppActionResult>;
}

export interface WorkflowStep {
  app: AppName;
  status: "pending" | "completed" | "failed";
  attempts: number;
  idempotencyKey: string;
  result?: AppActionResult;
  error?: string;
}

export interface IncidentWorkflow {
  schemaVersion: "dadieng.multi-app-workflow.v1";
  workflowId: string;
  inputHash: `sha256:${string}`;
  status: "running" | "completed" | "failed";
  steps: WorkflowStep[];
}

export interface WorkflowStore {
  load(workflowId: string): Promise<IncidentWorkflow | undefined>;
  save(workflow: IncidentWorkflow): Promise<void>;
  withLock<T>(workflowId: string, operation: () => Promise<T>): Promise<T>;
}

export class InMemoryWorkflowStore implements WorkflowStore {
  private readonly workflows = new Map<string, IncidentWorkflow>();
  private readonly queues = new Map<string, Promise<void>>();

  async load(workflowId: string): Promise<IncidentWorkflow | undefined> {
    const value = this.workflows.get(workflowId);
    return value ? structuredClone(value) : undefined;
  }

  async save(workflow: IncidentWorkflow): Promise<void> {
    this.workflows.set(workflow.workflowId, structuredClone(workflow));
  }

  async withLock<T>(workflowId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(workflowId) ?? Promise.resolve();
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.then(() => gate);
    this.queues.set(workflowId, tail);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.queues.get(workflowId) === tail) this.queues.delete(workflowId);
    }
  }
}

export class FileWorkflowStore implements WorkflowStore {
  private readonly queues = new Map<string, Promise<void>>();
  private readonly root: string;

  constructor(root: string) {
    if (!root.trim()) throw new Error("Workflow storage root is required");
    this.root = resolve(root);
  }

  private file(workflowId: string): string {
    return resolve(this.root, `${createHash("sha256").update(workflowId).digest("hex")}.json`);
  }

  async load(workflowId: string): Promise<IncidentWorkflow | undefined> {
    try {
      const parsed = JSON.parse(await readFile(this.file(workflowId), "utf8")) as IncidentWorkflow;
      if (parsed.schemaVersion !== "dadieng.multi-app-workflow.v1" || parsed.workflowId !== workflowId || !HASH.test(parsed.inputHash) || !Array.isArray(parsed.steps)) {
        throw new Error("Stored workflow is invalid");
      }
      return parsed;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }

  async save(workflow: IncidentWorkflow): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const file = this.file(workflow.workflowId);
    const temporary = `${file}.${randomUUID()}.tmp`;
    await writeFile(temporary, JSON.stringify(workflow), { encoding: "utf8", mode: 0o600 });
    await rename(temporary, file);
  }

  async withLock<T>(workflowId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(workflowId) ?? Promise.resolve();
    let release = (): void => undefined;
    const gate = new Promise<void>((resolveGate) => { release = resolveGate; });
    const tail = previous.then(() => gate);
    this.queues.set(workflowId, tail);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.queues.get(workflowId) === tail) this.queues.delete(workflowId);
    }
  }
}

export class AppRequestError extends Error {
  constructor(message: string, readonly retryable: boolean) {
    super(message);
    this.name = "AppRequestError";
  }
}

export interface CoordinatorOptions {
  store: WorkflowStore;
  apps: [IncidentApp, IncidentApp, IncidentApp];
  maxAttempts?: number;
  wait?: (milliseconds: number) => Promise<void>;
}

const APP_ORDER: AppName[] = ["github", "slack", "notion"];
const HASH = /^sha256:[a-f0-9]{64}$/;
const FORBIDDEN = /(https?:\/\/|process\.env|api[_ -]?key|private[_ -]?key|bearer\s+[a-z0-9._-]+)/i;

function hash(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalIncident(incident: SanitizedIncident): string {
  return JSON.stringify({
    attackClass: incident.attackClass,
    evidenceHash: incident.evidenceHash,
    occurredAt: incident.occurredAt,
    receiptId: incident.receiptId,
    severity: incident.severity,
    summary: incident.summary,
  });
}

export function validateSanitizedIncident(incident: SanitizedIncident): void {
  if (!/^[a-zA-Z0-9._:-]{3,160}$/.test(incident.receiptId)) throw new Error("Invalid receipt ID");
  if (!/^[a-z0-9_:-]{3,80}$/i.test(incident.attackClass)) throw new Error("Invalid attack class");
  if (!HASH.test(incident.evidenceHash)) throw new Error("Invalid evidence commitment");
  if (!Number.isFinite(Date.parse(incident.occurredAt))) throw new Error("Invalid incident timestamp");
  if (incident.summary.length < 12 || incident.summary.length > 280) throw new Error("Summary must contain 12 to 280 characters");
  if (FORBIDDEN.test(incident.summary)) throw new Error("Summary may contain sensitive or destination data");
}

function freshWorkflow(incident: SanitizedIncident): IncidentWorkflow {
  const inputHash = hash(canonicalIncident(incident));
  const workflowId = `incident:${incident.receiptId}`;
  return {
    schemaVersion: "dadieng.multi-app-workflow.v1",
    workflowId,
    inputHash,
    status: "running",
    steps: APP_ORDER.map((app) => ({ app, status: "pending", attempts: 0, idempotencyKey: hash(`${workflowId}:${app}`) })),
  };
}

function safeError(error: unknown): string {
  return error instanceof AppRequestError ? error.message.slice(0, 120) : "External app action failed";
}

export async function coordinateIncident(incident: SanitizedIncident, options: CoordinatorOptions): Promise<IncidentWorkflow> {
  validateSanitizedIncident(incident);
  const expected = freshWorkflow(incident);
  return options.store.withLock(expected.workflowId, () => coordinateLocked(incident, options, expected));
}

async function coordinateLocked(incident: SanitizedIncident, options: CoordinatorOptions, expected: IncidentWorkflow): Promise<IncidentWorkflow> {
  const maxAttempts = options.maxAttempts ?? 3;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) throw new Error("maxAttempts must be an integer from 1 to 10");
  const existing = await options.store.load(expected.workflowId);
  if (existing && existing.inputHash !== expected.inputHash) throw new Error("Receipt ID was already used with different incident data");
  const workflow = existing ?? expected;
  if (workflow.status === "completed") return workflow;

  const apps = new Map(options.apps.map((app) => [app.name, app]));
  if (apps.size !== APP_ORDER.length || APP_ORDER.some((name) => !apps.has(name))) {
    throw new Error("Coordinator requires exactly one GitHub, Slack, and Notion app");
  }

  workflow.status = "running";
  await options.store.save(workflow);
  const wait = options.wait ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));

  for (const step of workflow.steps) {
    if (step.status === "completed") continue;
    step.status = "pending";
    delete step.error;
    const app = apps.get(step.app)!;
    let runAttempts = 0;
    while (runAttempts < maxAttempts) {
      runAttempts += 1;
      step.attempts += 1;
      await options.store.save(workflow);
      try {
        step.result = await app.execute(incident, step.idempotencyKey);
        step.status = "completed";
        delete step.error;
        await options.store.save(workflow);
        break;
      } catch (error) {
        const retryable = error instanceof AppRequestError && error.retryable;
        step.error = safeError(error);
        if (!retryable || runAttempts >= maxAttempts) {
          step.status = "failed";
          workflow.status = "failed";
          await options.store.save(workflow);
          return workflow;
        }
        await wait(100 * 2 ** (runAttempts - 1));
      }
    }
  }

  workflow.status = "completed";
  await options.store.save(workflow);
  return workflow;
}

interface HttpOptions { fetch?: typeof fetch }

async function jsonRequest(fetcher: typeof fetch, url: string, init: RequestInit): Promise<Record<string, unknown>> {
  const response = await fetcher(url, init);
  if (!response.ok) throw new AppRequestError(`External app returned HTTP ${response.status}`, response.status === 429 || response.status >= 500);
  return await response.json() as Record<string, unknown>;
}

export class GitHubIncidentApp implements IncidentApp {
  readonly name = "github" as const;
  private readonly fetcher: typeof fetch;
  constructor(private readonly options: HttpOptions & { token: string; owner: string; repo: string }) { this.fetcher = options.fetch ?? fetch; }
  async execute(incident: SanitizedIncident, idempotencyKey: string): Promise<AppActionResult> {
    const marker = `<!-- dadieng:${idempotencyKey} -->`;
    const headers = { accept: "application/vnd.github+json", authorization: `Bearer ${this.options.token}`, "x-github-api-version": "2022-11-28" };
    const query = encodeURIComponent(`repo:${this.options.owner}/${this.options.repo} "dadieng:${idempotencyKey}" in:body is:issue`);
    const existing = await jsonRequest(this.fetcher, `https://api.github.com/search/issues?q=${query}`, { headers });
    const match = Array.isArray(existing.items) ? existing.items[0] as Record<string, unknown> | undefined : undefined;
    if (match) return { externalId: String(match.number), ...(typeof match.html_url === "string" ? { url: match.html_url } : {}) };
    const data = await jsonRequest(this.fetcher, `https://api.github.com/repos/${encodeURIComponent(this.options.owner)}/${encodeURIComponent(this.options.repo)}/issues`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ title: `[${incident.severity.toUpperCase()}] ${incident.attackClass}`, body: `${incident.summary}\n\nReceipt: \`${incident.receiptId}\`\nEvidence: \`${incident.evidenceHash}\`\n${marker}`, labels: ["security", "dadieng"] }),
    });
    return { externalId: String(data.number), ...(typeof data.html_url === "string" ? { url: data.html_url } : {}) };
  }
}

export class SlackIncidentApp implements IncidentApp {
  readonly name = "slack" as const;
  private readonly fetcher: typeof fetch;
  constructor(private readonly options: HttpOptions & { token: string; channel: string }) { this.fetcher = options.fetch ?? fetch; }
  async execute(incident: SanitizedIncident, idempotencyKey: string): Promise<AppActionResult> {
    const data = await jsonRequest(this.fetcher, "https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: { authorization: `Bearer ${this.options.token}`, "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({ channel: this.options.channel, client_msg_id: idempotencyKey.slice(7, 43), text: `Dadieng blocked a ${incident.severity} ${incident.attackClass} incident (${incident.receiptId}). ${incident.summary}` }),
    });
    if (data.ok !== true) throw new AppRequestError("Slack rejected the action", false);
    return { externalId: String(data.ts) };
  }
}

export class NotionIncidentApp implements IncidentApp {
  readonly name = "notion" as const;
  private readonly fetcher: typeof fetch;
  constructor(private readonly options: HttpOptions & { token: string; dataSourceId: string }) { this.fetcher = options.fetch ?? fetch; }
  async execute(incident: SanitizedIncident, _idempotencyKey: string): Promise<AppActionResult> {
    const headers = { authorization: `Bearer ${this.options.token}`, "content-type": "application/json", "notion-version": "2026-03-11" };
    const existing = await jsonRequest(this.fetcher, `https://api.notion.com/v1/data_sources/${encodeURIComponent(this.options.dataSourceId)}/query`, {
      method: "POST", headers, body: JSON.stringify({ filter: { property: "Receipt", rich_text: { equals: incident.receiptId } }, page_size: 1 }),
    });
    const match = Array.isArray(existing.results) ? existing.results[0] as Record<string, unknown> | undefined : undefined;
    if (match) return { externalId: String(match.id), ...(typeof match.url === "string" ? { url: match.url } : {}) };
    const data = await jsonRequest(this.fetcher, "https://api.notion.com/v1/pages", {
      method: "POST",
      headers,
      body: JSON.stringify({ parent: { type: "data_source_id", data_source_id: this.options.dataSourceId }, properties: {
        Name: { title: [{ text: { content: `${incident.attackClass} · ${incident.receiptId}` } }] },
        Severity: { select: { name: incident.severity } },
        Receipt: { rich_text: [{ text: { content: incident.receiptId } }] },
        Summary: { rich_text: [{ text: { content: incident.summary } }] },
      } }),
    });
    return { externalId: String(data.id), ...(typeof data.url === "string" ? { url: data.url } : {}) };
  }
}
