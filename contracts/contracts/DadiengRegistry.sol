// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IDadiengValidation} from "./interfaces/IDadiengRegistry.sol";

/// @title Dadieng Registry
/// @notice Immutable defense lifecycle, sanitized threat commitments, and scoped protocol controls.
contract DadiengRegistry is AccessControl {
    bytes32 public constant AUTHOR_ROLE = keccak256("AUTHOR_ROLE");
    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");
    bytes32 public constant RELEASE_MANAGER_ROLE = keccak256("RELEASE_MANAGER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    bytes32 public constant PUBLICATION_SCOPE = keccak256("PUBLICATION");
    bytes32 public constant PROMOTION_SCOPE = keccak256("PROMOTION");
    bytes32 public constant RECEIPT_SCOPE = keccak256("RECEIPT");

    enum DefenseStatus {
        None,
        Draft,
        Candidate,
        Stable,
        Rejected,
        Quarantined,
        Revoked
    }

    enum ReceiptResolution {
        Open,
        Linked,
        Resolved,
        Rejected
    }

    struct Defense {
        address author;
        uint256 authorAgentId;
        bool exists;
    }

    struct DefenseVersion {
        bytes32 defenseId;
        uint64 major;
        uint64 minor;
        uint64 patch;
        bytes32 manifestHash;
        bytes32 artifactHash;
        string manifestURI;
        uint256 authorAgentId;
        DefenseStatus status;
        uint64 createdAt;
        bytes32 supersedes;
        bytes32 replayReportHash;
        string replayReportURI;
        uint32 attackPassed;
        uint32 attackTotal;
        uint32 controlPassed;
        uint32 controlTotal;
    }

    struct ThreatReceipt {
        bytes32 receiptHash;
        bytes32 evidenceHash;
        bytes32 attackClass;
        uint256 reporterAgentId;
        address reporter;
        uint64 createdAt;
        ReceiptResolution resolution;
        bytes32 linkedVersionKey;
        bool exists;
    }

    struct PauseState {
        bool paused;
        uint64 expiresAt;
    }

    mapping(bytes32 defenseId => Defense) public defenses;
    mapping(bytes32 versionKey => DefenseVersion) private _versions;
    mapping(bytes32 receiptId => ThreatReceipt) private _receipts;
    mapping(bytes32 scope => PauseState) public pauseStates;

    IDadiengValidation public validationRegistry;
    bool public validationRegistryConfigured;

    event DefenseRegistered(bytes32 indexed defenseId, uint256 indexed authorAgentId);
    event DefenseVersionPublished(bytes32 indexed defenseId, bytes32 indexed versionKey, DefenseStatus status);
    event ReplayBundlePublished(bytes32 indexed versionKey, bytes32 indexed reportHash);
    event VersionStatusChanged(bytes32 indexed versionKey, DefenseStatus oldStatus, DefenseStatus newStatus);
    event VersionSafetyAction(
        bytes32 indexed versionKey,
        bytes32 indexed reasonCode,
        bytes32 evidenceHash,
        address indexed actor,
        uint64 timestamp,
        bytes32 replacementVersionKey
    );
    event ThreatReceiptPublished(bytes32 indexed receiptId, bytes32 indexed attackClass, uint256 indexed reporterAgentId);
    event ThreatReceiptLinked(bytes32 indexed receiptId, bytes32 indexed versionKey);
    event ThreatReceiptResolutionChanged(bytes32 indexed receiptId, ReceiptResolution oldResolution, ReceiptResolution newResolution);
    event ProtocolPaused(bytes32 indexed scope, address indexed actor, bool paused, bytes32 reasonCode, uint64 expiresAt);
    event ValidationRegistryConfigured(address indexed validationRegistry);

    error AlreadyExists();
    error InvalidInput();
    error InvalidState();
    error NotAuthor();
    error ScopePaused(bytes32 scope);
    error ValidationIncomplete();
    error ConfigurationLocked();

    constructor(address admin) {
        if (admin == address(0)) revert InvalidInput();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function versionKey(bytes32 defenseId, uint64 major, uint64 minor, uint64 patch) public pure returns (bytes32) {
        return keccak256(abi.encode(defenseId, major, minor, patch));
    }

    function setValidationRegistry(address registry) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (validationRegistryConfigured) revert ConfigurationLocked();
        if (registry == address(0) || registry.code.length == 0) revert InvalidInput();
        validationRegistry = IDadiengValidation(registry);
        validationRegistryConfigured = true;
        emit ValidationRegistryConfigured(registry);
    }

    function registerDefense(bytes32 defenseId, uint256 authorAgentId) external onlyRole(AUTHOR_ROLE) {
        _requireActive(PUBLICATION_SCOPE);
        if (defenseId == bytes32(0) || authorAgentId == 0) revert InvalidInput();
        if (defenses[defenseId].exists) revert AlreadyExists();
        defenses[defenseId] = Defense(msg.sender, authorAgentId, true);
        emit DefenseRegistered(defenseId, authorAgentId);
    }

    function publishVersion(
        bytes32 defenseId,
        uint64 major,
        uint64 minor,
        uint64 patch,
        bytes32 manifestHash,
        bytes32 artifactHash,
        string calldata manifestURI,
        bytes32 supersedes
    ) external onlyRole(AUTHOR_ROLE) returns (bytes32 key) {
        _requireActive(PUBLICATION_SCOPE);
        Defense memory defense = defenses[defenseId];
        if (!defense.exists) revert InvalidInput();
        if (defense.author != msg.sender) revert NotAuthor();
        if (manifestHash == bytes32(0) || artifactHash == bytes32(0) || bytes(manifestURI).length == 0) revert InvalidInput();
        if (supersedes != bytes32(0) && _versions[supersedes].defenseId != defenseId) revert InvalidInput();

        key = versionKey(defenseId, major, minor, patch);
        if (_versions[key].status != DefenseStatus.None) revert AlreadyExists();

        DefenseVersion storage item = _versions[key];
        item.defenseId = defenseId;
        item.major = major;
        item.minor = minor;
        item.patch = patch;
        item.manifestHash = manifestHash;
        item.artifactHash = artifactHash;
        item.manifestURI = manifestURI;
        item.authorAgentId = defense.authorAgentId;
        item.status = DefenseStatus.Draft;
        item.createdAt = uint64(block.timestamp);
        item.supersedes = supersedes;

        emit DefenseVersionPublished(defenseId, key, DefenseStatus.Draft);
    }

    function publishReplayBundle(
        bytes32 key,
        bytes32 reportHash,
        string calldata reportURI,
        uint32 attackPassed,
        uint32 attackTotal,
        uint32 controlPassed,
        uint32 controlTotal
    ) external onlyRole(AUTHOR_ROLE) {
        _requireActive(PUBLICATION_SCOPE);
        DefenseVersion storage item = _versions[key];
        if (item.status != DefenseStatus.Draft) revert InvalidState();
        if (defenses[item.defenseId].author != msg.sender) revert NotAuthor();
        if (
            reportHash == bytes32(0) || bytes(reportURI).length == 0 || attackTotal == 0 || controlTotal == 0
                || attackPassed > attackTotal || controlPassed > controlTotal
        ) revert InvalidInput();

        item.replayReportHash = reportHash;
        item.replayReportURI = reportURI;
        item.attackPassed = attackPassed;
        item.attackTotal = attackTotal;
        item.controlPassed = controlPassed;
        item.controlTotal = controlTotal;
        _changeStatus(key, item, DefenseStatus.Candidate);
        emit ReplayBundlePublished(key, reportHash);
    }

    function promoteVersion(bytes32 key) external onlyRole(RELEASE_MANAGER_ROLE) {
        _requireActive(PROMOTION_SCOPE);
        DefenseVersion storage item = _versions[key];
        if (item.status != DefenseStatus.Candidate) revert InvalidState();
        if (!validationRegistryConfigured || !validationRegistry.isValidationFinal(key)) revert ValidationIncomplete();
        _changeStatus(key, item, DefenseStatus.Stable);
    }

    function rejectVersion(bytes32 key, bytes32 reasonCode, bytes32 evidenceHash)
        external
        onlyRole(RELEASE_MANAGER_ROLE)
    {
        DefenseVersion storage item = _versions[key];
        if (item.status != DefenseStatus.Draft && item.status != DefenseStatus.Candidate) revert InvalidState();
        _requireReason(reasonCode, evidenceHash);
        _changeStatus(key, item, DefenseStatus.Rejected);
        emit VersionSafetyAction(key, reasonCode, evidenceHash, msg.sender, uint64(block.timestamp), bytes32(0));
    }

    function quarantineVersion(bytes32 key, bytes32 reasonCode, bytes32 evidenceHash, bytes32 replacementVersionKey)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        DefenseVersion storage item = _versions[key];
        if (
            item.status != DefenseStatus.Draft && item.status != DefenseStatus.Candidate
                && item.status != DefenseStatus.Stable
        ) revert InvalidState();
        _requireReason(reasonCode, evidenceHash);
        _requireReplacement(key, replacementVersionKey);
        _changeStatus(key, item, DefenseStatus.Quarantined);
        emit VersionSafetyAction(
            key, reasonCode, evidenceHash, msg.sender, uint64(block.timestamp), replacementVersionKey
        );
    }

    function revokeVersion(bytes32 key, bytes32 reasonCode, bytes32 evidenceHash, bytes32 replacementVersionKey)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        DefenseVersion storage item = _versions[key];
        if (item.status != DefenseStatus.Quarantined) revert InvalidState();
        _requireReason(reasonCode, evidenceHash);
        _requireReplacement(key, replacementVersionKey);
        _changeStatus(key, item, DefenseStatus.Revoked);
        emit VersionSafetyAction(
            key, reasonCode, evidenceHash, msg.sender, uint64(block.timestamp), replacementVersionKey
        );
    }

    function publishReceipt(
        bytes32 receiptId,
        bytes32 receiptHash,
        bytes32 evidenceHash,
        bytes32 attackClass,
        uint256 reporterAgentId
    ) external onlyRole(REPORTER_ROLE) {
        _requireActive(RECEIPT_SCOPE);
        if (
            receiptId == bytes32(0) || receiptHash == bytes32(0) || evidenceHash == bytes32(0)
                || attackClass == bytes32(0) || reporterAgentId == 0
        ) revert InvalidInput();
        if (_receipts[receiptId].exists) revert AlreadyExists();
        _receipts[receiptId] = ThreatReceipt({
            receiptHash: receiptHash,
            evidenceHash: evidenceHash,
            attackClass: attackClass,
            reporterAgentId: reporterAgentId,
            reporter: msg.sender,
            createdAt: uint64(block.timestamp),
            resolution: ReceiptResolution.Open,
            linkedVersionKey: bytes32(0),
            exists: true
        });
        emit ThreatReceiptPublished(receiptId, attackClass, reporterAgentId);
    }

    function linkDefense(bytes32 receiptId, bytes32 key) external onlyRole(RELEASE_MANAGER_ROLE) {
        _requireActive(RECEIPT_SCOPE);
        ThreatReceipt storage receipt = _receipts[receiptId];
        if (!receipt.exists || _versions[key].status == DefenseStatus.None) revert InvalidInput();
        if (receipt.resolution != ReceiptResolution.Open) revert InvalidState();
        receipt.linkedVersionKey = key;
        receipt.resolution = ReceiptResolution.Linked;
        emit ThreatReceiptLinked(receiptId, key);
        emit ThreatReceiptResolutionChanged(receiptId, ReceiptResolution.Open, ReceiptResolution.Linked);
    }

    function updateResolution(bytes32 receiptId, ReceiptResolution resolution)
        external
        onlyRole(RELEASE_MANAGER_ROLE)
    {
        _requireActive(RECEIPT_SCOPE);
        ThreatReceipt storage receipt = _receipts[receiptId];
        if (!receipt.exists || resolution == ReceiptResolution.Open || resolution == ReceiptResolution.Linked) {
            revert InvalidInput();
        }
        if (receipt.resolution != ReceiptResolution.Open && receipt.resolution != ReceiptResolution.Linked) revert InvalidState();
        ReceiptResolution oldResolution = receipt.resolution;
        receipt.resolution = resolution;
        emit ThreatReceiptResolutionChanged(receiptId, oldResolution, resolution);
    }

    function setProtocolPause(bytes32 scope, bool paused, uint64 expiresAt, bytes32 reasonCode)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        if (!_knownScope(scope) || reasonCode == bytes32(0)) revert InvalidInput();
        if (paused && expiresAt != 0 && expiresAt <= block.timestamp) revert InvalidInput();
        pauseStates[scope] = PauseState(paused, paused ? expiresAt : 0);
        emit ProtocolPaused(scope, msg.sender, paused, reasonCode, paused ? expiresAt : 0);
    }

    function isPaused(bytes32 scope) public view returns (bool) {
        PauseState memory state = pauseStates[scope];
        return state.paused && (state.expiresAt == 0 || block.timestamp < state.expiresAt);
    }

    function getVersion(bytes32 key) external view returns (DefenseVersion memory) {
        return _versions[key];
    }

    function getReceipt(bytes32 receiptId) external view returns (ThreatReceipt memory) {
        return _receipts[receiptId];
    }

    function getVersionValidationData(bytes32 key)
        external
        view
        returns (uint8 status, address author, uint256 authorAgentId, bool exists)
    {
        DefenseVersion storage item = _versions[key];
        Defense storage defense = defenses[item.defenseId];
        return (uint8(item.status), defense.author, item.authorAgentId, item.status != DefenseStatus.None);
    }

    function _changeStatus(bytes32 key, DefenseVersion storage item, DefenseStatus newStatus) private {
        DefenseStatus oldStatus = item.status;
        item.status = newStatus;
        emit VersionStatusChanged(key, oldStatus, newStatus);
    }

    function _requireActive(bytes32 scope) private view {
        if (isPaused(scope)) revert ScopePaused(scope);
    }

    function _requireReason(bytes32 reasonCode, bytes32 evidenceHash) private pure {
        if (reasonCode == bytes32(0) || evidenceHash == bytes32(0)) revert InvalidInput();
    }

    function _requireReplacement(bytes32 key, bytes32 replacementVersionKey) private view {
        if (replacementVersionKey != bytes32(0)) {
            DefenseStatus replacementStatus = _versions[replacementVersionKey].status;
            if (
                replacementVersionKey == key
                    || (replacementStatus != DefenseStatus.Candidate && replacementStatus != DefenseStatus.Stable)
            ) {
                revert InvalidInput();
            }
        }
    }

    function _knownScope(bytes32 scope) private pure returns (bool) {
        return scope == PUBLICATION_SCOPE || scope == PROMOTION_SCOPE || scope == RECEIPT_SCOPE;
    }
}
