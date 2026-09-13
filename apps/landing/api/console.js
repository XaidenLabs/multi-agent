import worker from '../worker/index.js';

export default async function handler(request, response) {
  const host = request.headers.host ?? 'localhost';
  const protocol = request.headers['x-forwarded-proto'] ?? 'https';
  const upstream = await worker.fetch(
    new Request(new URL(request.url ?? '/api/console', `${protocol}://${host}`), { method: request.method }),
    { ENVIO_GRAPHQL_URL: process.env.ENVIO_GRAPHQL_URL },
  );

  response.statusCode = upstream.status;
  upstream.headers.forEach((value, key) => response.setHeader(key, value));
  response.end(Buffer.from(await upstream.arrayBuffer()));
}
