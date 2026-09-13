# @dadieng/defense-module

Portable, content-addressed defense bundles for the Dadieng SDK.

Each bundle contains four files:

- `manifest.json`: identity, version, compatibility, permissions, and hashes.
- `artifact.json`: deterministic declarative rules.
- `suite.json`: attack and control cases with expected outcomes.
- `sbom.json`: the module software bill of materials.

The local loader validates every schema, checks identity consistency and SHA-256 commitments, and only executes the constrained `dadieng-rules` runtime. TypeScript and WebAssembly manifests are reserved for a future isolated executor and are rejected by the local loader.

```ts
import { loadDefenseBundle, readDefenseBundle, runDefenseSuite } from "@dadieng/defense-module";

const bundle = await readDefenseBundle("./defenses/mcp-boundary");
const suite = runDefenseSuite(bundle);
if (!suite.passed) throw new Error("Defense suite failed");

const defense = loadDefenseBundle(bundle);
```
