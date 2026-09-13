# @dadieng/replay-engine

The Dadieng replay engine verifies a Defense Module bundle, runs its attack and legitimate-control cases through one deterministic assertion path, and produces a content-addressed `dadieng.replay-report.v2` report.

Each report records:

- the exact manifest, artifact, suite, and SBOM hashes;
- worker image and dependency-lock hashes;
- seed, runtime, network, filesystem, and clock policy;
- every expected and actual outcome without copying fixture content;
- attack effectiveness, control utility, and latency percentiles;
- candidate release thresholds and the resulting eligibility decision;
- a SHA-256 commitment covering the complete report.

```ts
import { runReplay, verifyReplayReport } from "@dadieng/replay-engine";

const report = runReplay(bundle, {
  environment: {
    imageDigest,
    dependencyLockHash,
    runtime: "node-22",
    seed: 42,
    network: "none",
    filesystem: "read-only",
    clock: "deterministic",
  },
});

verifyReplayReport(report, bundle);
```

Use `pnpm replay:demo` from the repository root to print the reference report. Use `pnpm replay:report` to regenerate the committed report under `replays/mcp-boundary`.

The committed reference report uses injected deterministic measurements to prove report reproducibility; it is not a hardware benchmark. Runs that publish performance claims should use the default wall-clock runtime or an independently calibrated worker and identify that environment by digest.

Phase 6 executes only the non-executable `dadieng-rules` format established in Phase 4. This removes ambient I/O from module evaluation, but it is not a general OS sandbox. TypeScript and WebAssembly modules remain rejected until a hardened isolated worker exists.
