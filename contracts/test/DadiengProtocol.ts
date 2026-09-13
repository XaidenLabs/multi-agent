import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { keccak256, stringToHex } from "viem";

const { viem, networkHelpers } = await network.create();

const id = (value: string) => keccak256(stringToHex(value));

async function deployProtocol() {
  const wallets = await viem.getWalletClients();
  const admin = wallets[0]!;
  const author = wallets[1]!;
  const validatorOne = wallets[2]!;
  const validatorTwo = wallets[3]!;
  const releaseManager = wallets[4]!;
  const guardian = wallets[5]!;
  const reporter = wallets[6]!;
  const treasury = wallets[7]!;
  const recipient = wallets[8]!;
  const outsider = wallets[9]!;

  const registry = await viem.deployContract("DadiengRegistry", [admin.account.address]);
  const validation = await viem.deployContract("DadiengValidation", [registry.address, admin.account.address, 2]);
  const rewards = await viem.deployContract("DadiengRewards", [registry.address, admin.account.address]);

  await registry.write.setValidationRegistry([validation.address], { account: admin.account });
  await registry.write.grantRole([await registry.read.AUTHOR_ROLE(), author.account.address], { account: admin.account });
  await registry.write.grantRole([await registry.read.RELEASE_MANAGER_ROLE(), releaseManager.account.address], {
    account: admin.account,
  });
  await registry.write.grantRole([await registry.read.GUARDIAN_ROLE(), guardian.account.address], {
    account: admin.account,
  });
  await registry.write.grantRole([await registry.read.REPORTER_ROLE(), reporter.account.address], {
    account: admin.account,
  });

  await validation.write.setValidatorIdentity([validatorOne.account.address, 2001n, true], { account: admin.account });
  await validation.write.setValidatorIdentity([validatorTwo.account.address, 2002n, true], { account: admin.account });
  await validation.write.grantRole([await validation.read.GUARDIAN_ROLE(), guardian.account.address], {
    account: admin.account,
  });

  await rewards.write.grantRole([await rewards.read.USAGE_COMMITTER_ROLE(), reporter.account.address], {
    account: admin.account,
  });
  await rewards.write.grantRole([await rewards.read.RELEASE_MANAGER_ROLE(), releaseManager.account.address], {
    account: admin.account,
  });
  await rewards.write.grantRole([await rewards.read.GUARDIAN_ROLE(), guardian.account.address], {
    account: admin.account,
  });
  await rewards.write.grantRole([await rewards.read.TREASURY_ROLE(), treasury.account.address], {
    account: admin.account,
  });

  return {
    registry,
    validation,
    rewards,
    admin,
    author,
    validatorOne,
    validatorTwo,
    releaseManager,
    guardian,
    reporter,
    treasury,
    recipient,
    outsider,
  };
}

async function publishCandidate(fixture: Awaited<ReturnType<typeof deployProtocol>>, suffix = "one") {
  const defenseId = id(`defense-${suffix}`);
  await fixture.registry.write.registerDefense([defenseId, 1001n], { account: fixture.author.account });
  const versionKey = await fixture.registry.read.versionKey([defenseId, 1n, 0n, 0n]);
  await fixture.registry.write.publishVersion(
    [
      defenseId,
      1n,
      0n,
      0n,
      id(`manifest-${suffix}`),
      id(`artifact-${suffix}`),
      `ipfs://manifest-${suffix}`,
      stringToHex("", { size: 32 }),
    ],
    { account: fixture.author.account },
  );
  await fixture.registry.write.publishReplayBundle(
    [versionKey, id(`replay-${suffix}`), `ipfs://replay-${suffix}`, 20, 20, 20, 20],
    { account: fixture.author.account },
  );
  return { defenseId, versionKey };
}

const passingAttestation = (suffix: string) => ({
  passed: true,
  reportHash: id(`validator-report-${suffix}`),
  reportURI: `ipfs://validator-report-${suffix}`,
  attackPassed: 20,
  attackTotal: 20,
  controlPassed: 20,
  controlTotal: 20,
});

async function publishStable(fixture: Awaited<ReturnType<typeof deployProtocol>>, suffix: string) {
  const candidate = await publishCandidate(fixture, suffix);
  await fixture.validation.write.submitAttestation([candidate.versionKey, passingAttestation(`${suffix}-one`)], {
    account: fixture.validatorOne.account,
  });
  await fixture.validation.write.submitAttestation([candidate.versionKey, passingAttestation(`${suffix}-two`)], {
    account: fixture.validatorTwo.account,
  });
  await fixture.validation.write.finalizeValidation([candidate.versionKey]);
  await fixture.registry.write.promoteVersion([candidate.versionKey], { account: fixture.releaseManager.account });
  return candidate;
}

describe("Dadieng Phase 9 protocol", { concurrency: false }, function () {
  it("publishes an immutable draft and requires the exact registered author", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const defenseId = id("defense-authorship");

    await viem.assertions.emitWithArgs(
      fixture.registry.write.registerDefense([defenseId, 1001n], { account: fixture.author.account }),
      fixture.registry,
      "DefenseRegistered",
      [defenseId, 1001n],
    );

    await viem.assertions.revertWithCustomError(
      fixture.registry.write.publishVersion(
        [defenseId, 1n, 0n, 0n, id("manifest"), id("artifact"), "ipfs://manifest", stringToHex("", { size: 32 })],
        { account: fixture.outsider.account },
      ),
      fixture.registry,
      "AccessControlUnauthorizedAccount",
    );

    const versionKey = await fixture.registry.read.versionKey([defenseId, 1n, 0n, 0n]);
    await fixture.registry.write.publishVersion(
      [defenseId, 1n, 0n, 0n, id("manifest"), id("artifact"), "ipfs://manifest", stringToHex("", { size: 32 })],
      { account: fixture.author.account },
    );
    const version = await fixture.registry.read.getVersion([versionKey]);
    assert.equal(version.status, 1);
    assert.equal(version.authorAgentId, 1001n);

    await viem.assertions.revertWithCustomError(
      fixture.registry.write.publishVersion(
        [defenseId, 1n, 0n, 0n, id("changed"), id("changed"), "ipfs://changed", stringToHex("", { size: 32 })],
        { account: fixture.author.account },
      ),
      fixture.registry,
      "AlreadyExists",
    );
  });

  it("requires a complete replay bundle before a version becomes a candidate", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const defenseId = id("defense-replay");
    await fixture.registry.write.registerDefense([defenseId, 1001n], { account: fixture.author.account });
    const versionKey = await fixture.registry.read.versionKey([defenseId, 1n, 0n, 0n]);
    await fixture.registry.write.publishVersion(
      [defenseId, 1n, 0n, 0n, id("manifest-r"), id("artifact-r"), "ipfs://manifest-r", stringToHex("", { size: 32 })],
      { account: fixture.author.account },
    );

    await viem.assertions.revertWithCustomError(
      fixture.registry.write.publishReplayBundle(
        [versionKey, id("report"), "ipfs://report", 21, 20, 20, 20],
        { account: fixture.author.account },
      ),
      fixture.registry,
      "InvalidInput",
    );
    await fixture.registry.write.publishReplayBundle(
      [versionKey, id("report"), "ipfs://report", 20, 20, 20, 20],
      { account: fixture.author.account },
    );
    assert.equal((await fixture.registry.read.getVersion([versionKey])).status, 2);
  });

  it("deduplicates validator identity, forbids self-attestation, and enforces the independent threshold", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishCandidate(fixture, "threshold");

    await viem.assertions.revertWithCustomError(
      fixture.validation.write.setValidatorIdentity([fixture.outsider.account.address, 2001n, true], {
        account: fixture.admin.account,
      }),
      fixture.validation,
      "InvalidIdentity",
    );

    await fixture.validation.write.setValidatorIdentity([fixture.author.account.address, 1001n, true], {
      account: fixture.admin.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.validation.write.submitAttestation([versionKey, passingAttestation("self")], {
        account: fixture.author.account,
      }),
      fixture.validation,
      "SelfAttestation",
    );

    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("one")], {
      account: fixture.validatorOne.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.validation.write.finalizeValidation([versionKey]),
      fixture.validation,
      "InvalidState",
    );
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("two")], {
      account: fixture.validatorTwo.account,
    });
    await fixture.validation.write.finalizeValidation([versionKey]);
    assert.equal(await fixture.validation.read.isValidationFinal([versionKey]), true);

    await viem.assertions.emitWithArgs(
      fixture.registry.write.promoteVersion([versionKey], { account: fixture.releaseManager.account }),
      fixture.registry,
      "VersionStatusChanged",
      [versionKey, 2, 3],
    );
  });

  it("lets a guardian invalidate a challenged attestation before finalization", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishCandidate(fixture, "challenge");
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("c-one")], {
      account: fixture.validatorOne.account,
    });
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("c-two")], {
      account: fixture.validatorTwo.account,
    });
    await fixture.validation.write.challengeAttestation(
      [versionKey, 2002n, id("bad-environment"), id("challenge-evidence")],
      { account: fixture.guardian.account },
    );
    assert.equal(await fixture.validation.read.passingAttestations([versionKey]), 1);
    await viem.assertions.revertWithCustomError(
      fixture.validation.write.finalizeValidation([versionKey]),
      fixture.validation,
      "InvalidState",
    );
  });

  it("does not count failed, malformed, or duplicate validator attestations", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishCandidate(fixture, "attestation-guards");
    const failed = { ...passingAttestation("failed"), passed: false };
    await fixture.validation.write.submitAttestation([versionKey, failed], {
      account: fixture.validatorOne.account,
    });
    assert.equal(await fixture.validation.read.passingAttestations([versionKey]), 0);
    assert.equal((await fixture.validation.read.getAttestation([versionKey, 2001n])).passed, false);

    await viem.assertions.revertWithCustomError(
      fixture.validation.write.submitAttestation([versionKey, failed], { account: fixture.validatorOne.account }),
      fixture.validation,
      "AlreadyExists",
    );
    await viem.assertions.revertWithCustomError(
      fixture.validation.write.submitAttestation(
        [versionKey, { ...passingAttestation("malformed"), attackPassed: 21 }],
        { account: fixture.validatorTwo.account },
      ),
      fixture.validation,
      "InvalidInput",
    );
    await viem.assertions.revertWithCustomError(
      fixture.validation.write.setValidatorThreshold([0], { account: fixture.admin.account }),
      fixture.validation,
      "InvalidInput",
    );
  });

  it("rejects incomplete lifecycle paths and cross-defense supersession", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishCandidate(fixture, "not-yet-validated");
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.promoteVersion([versionKey], { account: fixture.releaseManager.account }),
      fixture.registry,
      "ValidationIncomplete",
    );

    const otherDefense = id("other-defense");
    await fixture.registry.write.registerDefense([otherDefense, 1001n], { account: fixture.author.account });
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.publishVersion(
        [otherDefense, 1n, 0n, 0n, id("other-manifest"), id("other-artifact"), "ipfs://other", versionKey],
        { account: fixture.author.account },
      ),
      fixture.registry,
      "InvalidInput",
    );

    const draftKey = await fixture.registry.read.versionKey([otherDefense, 2n, 0n, 0n]);
    await fixture.registry.write.publishVersion(
      [
        otherDefense,
        2n,
        0n,
        0n,
        id("draft-manifest"),
        id("draft-artifact"),
        "ipfs://draft",
        stringToHex("", { size: 32 }),
      ],
      { account: fixture.author.account },
    );
    await fixture.registry.write.rejectVersion([draftKey, id("failed-review"), id("review-evidence")], {
      account: fixture.releaseManager.account,
    });
    assert.equal((await fixture.registry.read.getVersion([draftKey])).status, 4);
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.publishReplayBundle([draftKey, id("late"), "ipfs://late", 1, 1, 1, 1], {
        account: fixture.author.account,
      }),
      fixture.registry,
      "InvalidState",
    );
  });

  it("quarantines with public evidence and makes revocation terminal", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishCandidate(fixture, "revoke");
    const reason = id("unsafe-output");
    const evidence = id("public-evidence");

    await viem.assertions.emit(
      fixture.registry.write.quarantineVersion([versionKey, reason, evidence, stringToHex("", { size: 32 })], {
        account: fixture.guardian.account,
      }),
      fixture.registry,
      "VersionSafetyAction",
    );
    await fixture.registry.write.revokeVersion([versionKey, reason, evidence, stringToHex("", { size: 32 })], {
      account: fixture.guardian.account,
    });
    assert.equal((await fixture.registry.read.getVersion([versionKey])).status, 6);
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.quarantineVersion([versionKey, reason, evidence, stringToHex("", { size: 32 })], {
        account: fixture.guardian.account,
      }),
      fixture.registry,
      "InvalidState",
    );
  });

  it("pauses mutation scopes without disabling reads and supports expiring emergency action", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const publicationScope = await fixture.registry.read.PUBLICATION_SCOPE();
    const expiresAt = BigInt((await networkHelpers.time.latest()) + 60);
    await fixture.registry.write.setProtocolPause([publicationScope, true, expiresAt, id("incident")], {
      account: fixture.guardian.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.registerDefense([id("paused-defense"), 1001n], { account: fixture.author.account }),
      fixture.registry,
      "ScopePaused",
    );
    assert.equal((await fixture.registry.read.defenses([id("unknown")]))[2], false);
    await networkHelpers.time.increase(61);
    await fixture.registry.write.registerDefense([id("after-expiry"), 1001n], { account: fixture.author.account });
  });

  it("stores only sanitized threat commitments and controls receipt resolution", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const receiptId = id("receipt");
    await viem.assertions.emitWithArgs(
      fixture.registry.write.publishReceipt(
        [receiptId, id("public-receipt"), id("encrypted-evidence"), id("prompt-injection"), 3001n],
        { account: fixture.reporter.account },
      ),
      fixture.registry,
      "ThreatReceiptPublished",
      [receiptId, id("prompt-injection"), 3001n],
    );
    const receipt = await fixture.registry.read.getReceipt([receiptId]);
    assert.equal(receipt.receiptHash, id("public-receipt"));
    assert.equal(receipt.evidenceHash, id("encrypted-evidence"));
    assert.equal(receipt.resolution, 0);
    assert.equal(Object.hasOwn(receipt, "rawEvidence"), false);
  });

  it("links and resolves receipts while the receipt scope is active", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishCandidate(fixture, "receipt-link");
    const receiptId = id("linked-receipt");
    await fixture.registry.write.publishReceipt(
      [receiptId, id("linked-public"), id("linked-evidence"), id("tool-poisoning"), 3001n],
      { account: fixture.reporter.account },
    );
    await fixture.registry.write.linkDefense([receiptId, versionKey], { account: fixture.releaseManager.account });
    await fixture.registry.write.updateResolution([receiptId, 2], { account: fixture.releaseManager.account });
    const receipt = await fixture.registry.read.getReceipt([receiptId]);
    assert.equal(receipt.linkedVersionKey, versionKey);
    assert.equal(receipt.resolution, 2);

    const receiptScope = await fixture.registry.read.RECEIPT_SCOPE();
    await fixture.registry.write.setProtocolPause([receiptScope, true, 0n, id("receipt-incident")], {
      account: fixture.guardian.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.publishReceipt(
        [id("paused-receipt"), id("paused-public"), id("paused-evidence"), id("unknown-attack"), 3001n],
        { account: fixture.reporter.account },
      ),
      fixture.registry,
      "ScopePaused",
    );
  });

  it("commits usage, requires finalization and funding, then pays a claim exactly once", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const epoch = 7n;
    const root = id("usage-root");
    const { versionKey } = await publishCandidate(fixture, "usage-stable");
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("usage-one")], {
      account: fixture.validatorOne.account,
    });
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("usage-two")], {
      account: fixture.validatorTwo.account,
    });
    await fixture.validation.write.finalizeValidation([versionKey]);
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.commitUsageBatch([epoch, 4001n, versionKey, root, 12n], {
        account: fixture.reporter.account,
      }),
      fixture.rewards,
      "InvalidState",
    );
    await fixture.registry.write.promoteVersion([versionKey], { account: fixture.releaseManager.account });
    const batchId = await fixture.rewards.read.batchId([epoch, 4001n, versionKey, root]);

    await fixture.rewards.write.commitUsageBatch([epoch, 4001n, versionKey, root, 12n], {
      account: fixture.reporter.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.allocateRewards([batchId, [fixture.recipient.account.address], [2n]], {
        account: fixture.releaseManager.account,
      }),
      fixture.rewards,
      "InvalidInput",
    );
    await fixture.rewards.write.finalizeBatch([batchId], { account: fixture.releaseManager.account });
    await fixture.rewards.write.fundEpoch([epoch], { account: fixture.treasury.account, value: 10n ** 18n });
    await fixture.rewards.write.allocateRewards([batchId, [fixture.recipient.account.address], [10n ** 17n]], {
      account: fixture.releaseManager.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.allocateRewards([batchId, [fixture.outsider.account.address], [1n]], {
        account: fixture.releaseManager.account,
      }),
      fixture.rewards,
      "InvalidInput",
    );
    await viem.assertions.balancesHaveChanged(
      fixture.rewards.write.claimReward([epoch], { account: fixture.recipient.account }),
      [
        { address: fixture.recipient.account.address, amount: 10n ** 17n },
        { address: fixture.rewards.address, amount: -(10n ** 17n) },
      ],
    );
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.claimReward([epoch], { account: fixture.recipient.account }),
      fixture.rewards,
      "InvalidState",
    );
  });

  it("blocks challenged usage batches and independently pauses reward claims", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const root = id("challenged-root");
    const { versionKey } = await publishCandidate(fixture, "challenged-usage");
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("challenged-one")], {
      account: fixture.validatorOne.account,
    });
    await fixture.validation.write.submitAttestation([versionKey, passingAttestation("challenged-two")], {
      account: fixture.validatorTwo.account,
    });
    await fixture.validation.write.finalizeValidation([versionKey]);
    await fixture.registry.write.promoteVersion([versionKey], { account: fixture.releaseManager.account });
    const batchId = await fixture.rewards.read.batchId([8n, 4001n, versionKey, root]);
    await fixture.rewards.write.commitUsageBatch([8n, 4001n, versionKey, root, 1n], {
      account: fixture.reporter.account,
    });
    await fixture.rewards.write.challengeBatch([batchId, id("fraud"), id("fraud-proof")], {
      account: fixture.guardian.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.finalizeBatch([batchId], { account: fixture.releaseManager.account }),
      fixture.rewards,
      "InvalidState",
    );

    const claimsScope = await fixture.rewards.read.CLAIMS_SCOPE();
    await fixture.rewards.write.setProtocolPause([claimsScope, true, 0n, id("claims-incident")], {
      account: fixture.guardian.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.claimReward([8n], { account: fixture.recipient.account }),
      fixture.rewards,
      "ScopePaused",
    );
  });

  it("rejects duplicate batches, underfunded allocations, and allocations after a recipient claims", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    const { versionKey } = await publishStable(fixture, "reward-guards");
    const epoch = 9n;
    const firstRoot = id("first-root");
    const firstBatch = await fixture.rewards.read.batchId([epoch, 4001n, versionKey, firstRoot]);

    await fixture.rewards.write.commitUsageBatch([epoch, 4001n, versionKey, firstRoot, 2n], {
      account: fixture.reporter.account,
    });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.commitUsageBatch([epoch, 4001n, versionKey, firstRoot, 2n], {
        account: fixture.reporter.account,
      }),
      fixture.rewards,
      "AlreadyExists",
    );
    await fixture.rewards.write.finalizeBatch([firstBatch], { account: fixture.releaseManager.account });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.allocateRewards([firstBatch, [fixture.recipient.account.address], [10n]], {
        account: fixture.releaseManager.account,
      }),
      fixture.rewards,
      "InsufficientFunding",
    );
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.fundEpoch([epoch], { account: fixture.treasury.account, value: 0n }),
      fixture.rewards,
      "InvalidInput",
    );
    await fixture.rewards.write.fundEpoch([epoch], { account: fixture.treasury.account, value: 100n });
    await fixture.rewards.write.allocateRewards([firstBatch, [fixture.recipient.account.address], [10n]], {
      account: fixture.releaseManager.account,
    });
    await fixture.rewards.write.claimReward([epoch], { account: fixture.recipient.account });

    const secondRoot = id("second-root");
    const secondBatch = await fixture.rewards.read.batchId([epoch, 4001n, versionKey, secondRoot]);
    await fixture.rewards.write.commitUsageBatch([epoch, 4001n, versionKey, secondRoot, 1n], {
      account: fixture.reporter.account,
    });
    await fixture.rewards.write.finalizeBatch([secondBatch], { account: fixture.releaseManager.account });
    await viem.assertions.revertWithCustomError(
      fixture.rewards.write.allocateRewards([secondBatch, [fixture.recipient.account.address], [1n]], {
        account: fixture.releaseManager.account,
      }),
      fixture.rewards,
      "InvalidInput",
    );
  });

  it("locks the validation dependency after one configuration", async function () {
    const fixture = await networkHelpers.loadFixture(deployProtocol);
    await viem.assertions.revertWithCustomError(
      fixture.registry.write.setValidationRegistry([fixture.validation.address], { account: fixture.admin.account }),
      fixture.registry,
      "ConfigurationLocked",
    );
  });
});
