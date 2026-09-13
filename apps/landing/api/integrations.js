const required = {
  github: ['GITHUB_TOKEN', 'GITHUB_OWNER', 'GITHUB_REPO'],
  slack: ['SLACK_BOT_TOKEN', 'SLACK_CHANNEL_ID'],
  notion: ['NOTION_TOKEN', 'NOTION_DATA_SOURCE_ID'],
};

export default function handler(request, response) {
  if (request.method !== 'GET') {
    response.status(405).json({ error: 'Method not allowed' });
    return;
  }
  const configured = Object.fromEntries(Object.entries(required).map(([app, names]) => [app, names.every((name) => Boolean(process.env[name]))]));
  response.setHeader('cache-control', 'no-store');
  response.setHeader('x-content-type-options', 'nosniff');
  response.status(200).json({ mode: Object.values(configured).every(Boolean) ? 'configured' : 'preview-safe', configured, meaning: 'Configured means required secrets are present; it does not claim a successful remote API check.' });
}
