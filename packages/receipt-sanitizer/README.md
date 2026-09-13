# @dadieng/receipt-sanitizer

The Dadieng Threat Receipt pipeline separates public security intelligence from private incident evidence.

The pipeline:

1. Classifies the incident using versioned attack and capability taxonomies.
2. Builds a public receipt from controlled values without copying prompt or tool content.
3. Encrypts the exact normalized event and decision using AES-256-GCM.
4. Commits the public receipt to that encrypted envelope with SHA-256.
5. Produces a stable deduplication key independent of receipt IDs and encryption randomness.
6. Requires manual review for high and critical public disclosures.

```ts
import {
  createThreatReceiptPipeline,
  decryptThreatEvidence,
  verifyEvidenceCommitment,
} from "@dadieng/receipt-sanitizer";

const incident = createThreatReceiptPipeline(event, decision, {
  encryption: {
    key: evidenceKey, // exactly 32 bytes; obtain this from a secret manager
    keyId: "tenant-evidence-key-v1",
  },
});

if (!verifyEvidenceCommitment(incident.receipt, incident.encryptedEvidence)) {
  throw new Error("Evidence commitment mismatch");
}

const privateEvidence = decryptThreatEvidence(incident.encryptedEvidence, evidenceKey);
```

The encrypted envelope is returned to the caller for local or tenant-private storage. Dadieng does not persist plaintext or encryption keys. Phase 8 will provide the database and object-storage adapters; a later Mera integration can supply recoverable, namespaced key material without changing this receipt contract.
