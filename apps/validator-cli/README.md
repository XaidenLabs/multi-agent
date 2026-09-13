# Dadieng Validator CLI

The validator CLI is an independent application. It downloads a claimed job's public defense bundle, verifies the exact Monad commitments and validator identity, reruns the declared suite, signs its own report commitment, and submits the attestation from the validator's wallet.

It never downloads private incident evidence and refuses to sign the control plane's canonical replay report.

```text
dadieng-validator login --api http://127.0.0.1:3001 --token <validator-api-key>
dadieng-validator jobs list
dadieng-validator jobs claim <job-id>
dadieng-validator verify <job-id>
dadieng-validator attest <job-id>
```

`MONAD_RPC_URL`, `MONAD_PRIVATE_KEY`, and `DADIENG_REWARDS_ADDRESS` are required for verification and submission. Credentials, signed reports, and prepared transaction bytes are stored under `~/.config/dadieng-validator` with owner-only permissions. Set `DADIENG_VALIDATOR_HOME` to use another location.
