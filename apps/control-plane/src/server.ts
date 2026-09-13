import { createServer, type Server } from "node:http";
import { ControlPlaneHttpApp } from "./http.js";

const ADAPTER_BODY_LIMIT = 1_114_112;
const OVERSIZED_BODY_BYTES = 1_048_577;

export function createControlPlaneServer(app: ControlPlaneHttpApp): Server {
  return createServer(async (incoming, outgoing) => {
    try {
      const chunks: Buffer[] = [];
      let size = 0;
      let oversized = false;
      for await (const chunk of incoming) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.byteLength;
        if (size <= ADAPTER_BODY_LIMIT) chunks.push(buffer);
        else oversized = true;
      }

      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
        else if (value !== undefined) headers.set(name, value);
      }
      const body = oversized
        ? Buffer.alloc(OVERSIZED_BODY_BYTES)
        : chunks.length > 0 ? Buffer.concat(chunks) : undefined;
      const request = new Request(`http://localhost${incoming.url ?? "/"}`, {
        method: incoming.method ?? "GET",
        headers,
        ...(body ? { body } : {}),
      });
      const result = await app.handle(request, { clientId: incoming.socket.remoteAddress ?? "unknown" });
      outgoing.statusCode = result.status;
      result.headers.forEach((value, name) => outgoing.setHeader(name, value));
      outgoing.end(Buffer.from(await result.arrayBuffer()));
    } catch {
      outgoing.statusCode = 500;
      outgoing.setHeader("content-type", "application/problem+json");
      outgoing.end(JSON.stringify({
        type: "https://dadieng.dev/problems/server-adapter-error",
        title: "Server adapter error",
        status: 500,
        detail: "The HTTP adapter could not process the request.",
        requestId: "unavailable",
      }));
    }
  });
}
