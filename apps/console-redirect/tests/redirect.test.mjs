import assert from 'node:assert/strict';
import test from 'node:test';
import worker from '../worker/index.js';

test('permanently redirects the retired console site to the unified route', async () => {
  const response = await worker.fetch(new Request('https://old.example/defenses?version=stable'));
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://dadieng.dadiengalfred.chatgpt.site/console?version=stable');
});
