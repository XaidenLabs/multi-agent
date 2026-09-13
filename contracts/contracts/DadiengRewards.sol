// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IDadiengRegistry} from "./interfaces/IDadiengRegistry.sol";

/// @title Dadieng Usage and Rewards
/// @notice Merkle-root usage commitments and prefunded native-token reward claims.
contract DadiengRewards is AccessControl, ReentrancyGuard {
    bytes32 public constant USAGE_COMMITTER_ROLE = keccak256("USAGE_COMMITTER_ROLE");
    bytes32 public constant RELEASE_MANAGER_ROLE = keccak256("RELEASE_MANAGER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    bytes32 public constant USAGE_SCOPE = keccak256("USAGE");
    bytes32 public constant CLAIMS_SCOPE = keccak256("CLAIMS");
    uint8 private constant STABLE_STATUS = 3;

    struct UsageBatch {
        uint256 epoch;
        uint256 adopterId;
        bytes32 versionKey;
        bytes32 root;
        uint64 count;
        address committer;
        uint64 createdAt;
        bool challenged;
        bool finalized;
    }

    struct PauseState {
        bool paused;
        uint64 expiresAt;
    }

    mapping(bytes32 batchId => UsageBatch) private _batches;
    mapping(uint256 epoch => uint256 amount) public epochFunded;
    mapping(uint256 epoch => uint256 amount) public epochAllocated;
    mapping(uint256 epoch => mapping(address recipient => uint256 amount)) public rewardAllocations;
    mapping(uint256 epoch => mapping(address recipient => bool claimed)) public rewardClaimed;
    mapping(bytes32 batchId => bool allocated) public batchRewardsAllocated;
    mapping(bytes32 scope => PauseState) public pauseStates;

    IDadiengRegistry public immutable registry;

    event UsageBatchCommitted(uint256 indexed epoch, uint256 indexed adopterId, bytes32 indexed root);
    event UsageBatchRecorded(bytes32 indexed batchId, bytes32 indexed versionKey, uint64 count, address committer);
    event UsageBatchChallenged(bytes32 indexed batchId, bytes32 indexed reasonCode, bytes32 evidenceHash);
    event UsageBatchFinalized(bytes32 indexed batchId);
    event EpochFunded(uint256 indexed epoch, uint256 amount);
    event RewardsAllocated(bytes32 indexed batchId, uint256 indexed epoch, uint256 totalAmount);
    event RewardClaimed(uint256 indexed epoch, address indexed recipient, uint256 amount);
    event ProtocolPaused(bytes32 indexed scope, address indexed actor, bool paused, bytes32 reasonCode, uint64 expiresAt);

    error AlreadyExists();
    error InvalidInput();
    error InvalidState();
    error ScopePaused(bytes32 scope);
    error InsufficientFunding();
    error TransferFailed();

    constructor(address registryAddress, address admin) {
        if (registryAddress == address(0) || registryAddress.code.length == 0 || admin == address(0)) {
            revert InvalidInput();
        }
        registry = IDadiengRegistry(registryAddress);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function batchId(uint256 epoch, uint256 adopterId, bytes32 versionKey, bytes32 root)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(epoch, adopterId, versionKey, root));
    }

    function commitUsageBatch(uint256 epoch, uint256 adopterId, bytes32 versionKey, bytes32 root, uint64 count)
        external
        onlyRole(USAGE_COMMITTER_ROLE)
        returns (bytes32 id)
    {
        _requireActive(USAGE_SCOPE);
        if (adopterId == 0 || versionKey == bytes32(0) || root == bytes32(0) || count == 0) revert InvalidInput();
        (uint8 status,,, bool exists) = registry.getVersionValidationData(versionKey);
        if (!exists || status != STABLE_STATUS) revert InvalidState();
        id = batchId(epoch, adopterId, versionKey, root);
        if (_batches[id].createdAt != 0) revert AlreadyExists();
        _batches[id] = UsageBatch({
            epoch: epoch,
            adopterId: adopterId,
            versionKey: versionKey,
            root: root,
            count: count,
            committer: msg.sender,
            createdAt: uint64(block.timestamp),
            challenged: false,
            finalized: false
        });
        emit UsageBatchCommitted(epoch, adopterId, root);
        emit UsageBatchRecorded(id, versionKey, count, msg.sender);
    }

    function challengeBatch(bytes32 id, bytes32 reasonCode, bytes32 evidenceHash)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        UsageBatch storage batch = _batches[id];
        if (batch.createdAt == 0 || batch.challenged || batch.finalized) revert InvalidState();
        if (reasonCode == bytes32(0) || evidenceHash == bytes32(0)) revert InvalidInput();
        batch.challenged = true;
        emit UsageBatchChallenged(id, reasonCode, evidenceHash);
    }

    function finalizeBatch(bytes32 id) external onlyRole(RELEASE_MANAGER_ROLE) {
        _requireActive(USAGE_SCOPE);
        UsageBatch storage batch = _batches[id];
        if (batch.createdAt == 0 || batch.challenged || batch.finalized) revert InvalidState();
        batch.finalized = true;
        emit UsageBatchFinalized(id);
    }

    function fundEpoch(uint256 epoch) external payable onlyRole(TREASURY_ROLE) {
        if (msg.value == 0) revert InvalidInput();
        epochFunded[epoch] += msg.value;
        emit EpochFunded(epoch, msg.value);
    }

    function allocateRewards(bytes32 id, address[] calldata recipients, uint256[] calldata amounts)
        external
        onlyRole(RELEASE_MANAGER_ROLE)
    {
        _requireActive(USAGE_SCOPE);
        UsageBatch storage batch = _batches[id];
        uint256 length = recipients.length;
        if (
            !batch.finalized || batchRewardsAllocated[id] || length == 0 || length != amounts.length || length > 256
        ) revert InvalidInput();

        uint256 total;
        for (uint256 index; index < length; ++index) {
            if (
                recipients[index] == address(0) || amounts[index] == 0
                    || rewardClaimed[batch.epoch][recipients[index]]
            ) revert InvalidInput();
            total += amounts[index];
        }
        uint256 allocated = epochAllocated[batch.epoch];
        if (allocated + total > epochFunded[batch.epoch]) revert InsufficientFunding();
        epochAllocated[batch.epoch] = allocated + total;
        batchRewardsAllocated[id] = true;
        for (uint256 index; index < length; ++index) {
            rewardAllocations[batch.epoch][recipients[index]] += amounts[index];
        }
        emit RewardsAllocated(id, batch.epoch, total);
    }

    function claimReward(uint256 epoch) external nonReentrant {
        _requireActive(CLAIMS_SCOPE);
        uint256 amount = rewardAllocations[epoch][msg.sender];
        if (amount == 0 || rewardClaimed[epoch][msg.sender]) revert InvalidState();
        rewardClaimed[epoch][msg.sender] = true;
        (bool success,) = payable(msg.sender).call{value: amount}("");
        if (!success) revert TransferFailed();
        emit RewardClaimed(epoch, msg.sender, amount);
    }

    function setProtocolPause(bytes32 scope, bool paused, uint64 expiresAt, bytes32 reasonCode)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        if ((scope != USAGE_SCOPE && scope != CLAIMS_SCOPE) || reasonCode == bytes32(0)) revert InvalidInput();
        if (paused && expiresAt != 0 && expiresAt <= block.timestamp) revert InvalidInput();
        pauseStates[scope] = PauseState(paused, paused ? expiresAt : 0);
        emit ProtocolPaused(scope, msg.sender, paused, reasonCode, paused ? expiresAt : 0);
    }

    function isPaused(bytes32 scope) public view returns (bool) {
        PauseState memory state = pauseStates[scope];
        return state.paused && (state.expiresAt == 0 || block.timestamp < state.expiresAt);
    }

    function getUsageBatch(bytes32 id) external view returns (UsageBatch memory) {
        return _batches[id];
    }

    function _requireActive(bytes32 scope) private view {
        if (isPaused(scope)) revert ScopePaused(scope);
    }
}
