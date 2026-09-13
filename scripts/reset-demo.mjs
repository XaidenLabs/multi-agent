import { mkdir, realpath, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const workspace = await realpath(process.cwd());
const stateRoot = resolve(workspace, ".dadieng");
const target = resolve(stateRoot, "demo");
if (dirname(target) !== stateRoot || target === workspace) throw new Error("Refusing to reset an unsafe path");
await rm(target, { recursive: true, force: true });
await mkdir(target, { recursive: true, mode: 0o700 });
console.log("Dadieng demo state reset. Protocol databases and user files were not touched.");
