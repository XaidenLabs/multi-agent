import { FileWorkflowStore, GitHubIncidentApp, NotionIncidentApp, SlackIncidentApp, coordinateIncident, type SanitizedIncident } from "@dadieng/multi-app-agent";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

const incident: SanitizedIncident = {
  receiptId: required("DADIENG_DEMO_RECEIPT_ID"),
  attackClass: process.env.DADIENG_DEMO_ATTACK_CLASS ?? "tool_poisoning",
  severity: "critical",
  summary: "Untrusted tool output requested prohibited secret access and an external send.",
  evidenceHash: required("DADIENG_DEMO_EVIDENCE_HASH") as `sha256:${string}`,
  // A stable timestamp is part of the incident commitment. Requiring it keeps
  // an operator retry with the same receipt genuinely idempotent.
  occurredAt: required("DADIENG_DEMO_OCCURRED_AT"),
};

const workflow = await coordinateIncident(incident, {
  store: new FileWorkflowStore(process.env.DADIENG_WORKFLOW_ROOT ?? "./.dadieng/multi-app-workflows"),
  apps: [
    new GitHubIncidentApp({ token: required("GITHUB_TOKEN"), owner: required("GITHUB_OWNER"), repo: required("GITHUB_REPO") }),
    new SlackIncidentApp({ token: required("SLACK_BOT_TOKEN"), channel: required("SLACK_CHANNEL_ID") }),
    new NotionIncidentApp({ token: required("NOTION_TOKEN"), dataSourceId: required("NOTION_DATA_SOURCE_ID") }),
  ],
});

console.log(JSON.stringify(workflow, null, 2));
