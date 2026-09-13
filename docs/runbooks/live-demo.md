# Live testnet demo runbook

## Before the session

1. Set the real Monad RPC URL, deployed Registry/Validation/Rewards addresses,
   dedicated funded testnet keys, manifest signer, and ERC-8004 identities.
2. Start Postgres, apply migrations, and configure the private object store.
3. Start the control plane and at least two independently owned validators.
4. Start Envio from the deployed contract block and confirm freshness against a
   direct Monad read.
5. Configure the CRE secret and deployed callback URL, Dynamic environment,
   Qwen endpoint/key, and a PRF-capable passkey for the Mera ceremony.
6. Run `pnpm release:check` and `pnpm demo:final`. Never substitute production
   credentials or real customer evidence.

## Three-minute proof

1. Show two identical connected agents.
2. Send the hostile synthetic MCP result to Agent A; show its local block and
   sanitized receipt commitment.
3. Encrypt and decrypt the private synthetic evidence in a fresh passkey
   profile without a persisted symmetric key.
4. Trigger CRE; show Qwen's bounded taxonomy tool, replay report, and two
   independent validator attestations.
5. Confirm the Stable transaction directly on Monad, then show Envio's graph.
6. Sync Agent B and rerun the attack plus control. The attack must block and the
   control must pass.

Stop if any step is stale, below quorum, pending finality, or backed by an
unexpected chain/address. Never narrate pending state as finalized.
