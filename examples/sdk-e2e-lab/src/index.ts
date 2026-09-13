import { runSdkE2ELab } from "./lab.js";

const report = await runSdkE2ELab();
console.log(JSON.stringify(report, null, 2));
if (!report.passed) process.exitCode = 1;
