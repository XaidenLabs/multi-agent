// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IDadiengRegistry} from "./interfaces/IDadiengRegistry.sol";

/// @title Dadieng Validation Registry
/// @notice Independent, identity-deduplicated validator attestations for candidate defenses.
contract DadiengValidation is AccessControl {
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint8 private constant CANDIDATE_STATUS = 2;
    uint32 public constant MAX_THRESHOLD = 32;

    struct Attestation {
        bytes32 versionKey;
        uint256 validatorAgentId;
        bool passed;
        bytes32 reportHash;
        string reportURI;
        uint32 attackPassed;
        uint32 attackTotal;
        uint32 controlPassed;
        uint32 controlTotal;
        uint64 createdAt;
        bool challenged;
    }

    struct AttestationInput {
        bool passed;
        bytes32 reportHash;
        string reportURI;
        uint32 attackPassed;
        uint32 attackTotal;
        uint32 controlPassed;
        uint32 controlTotal;
    }

    IDadiengRegistry public immutable registry;
    uint32 public validatorThreshold;

    mapping(address validator => uint256 agentId) public validatorAgentIds;
    mapping(uint256 agentId => address validator) public agentIdOwners;
    mapping(bytes32 versionKey => mapping(uint256 agentId => Attestation)) private _attestations;
    mapping(bytes32 versionKey => uint32 count) public passingAttestations;
    mapping(bytes32 versionKey => bool) public isValidationFinal;

    event ValidatorIdentitySet(address indexed validator, uint256 indexed agentId, bool active);
    event ValidatorThresholdChanged(uint32 oldThreshold, uint32 newThreshold);
    event AttestationSubmitted(bytes32 indexed versionKey, uint256 indexed validatorAgentId, bool passed);
    event AttestationChallenged(
        bytes32 indexed versionKey, uint256 indexed validatorAgentId, bytes32 indexed reasonCode, bytes32 evidenceHash
    );
    event ValidationFinalized(bytes32 indexed versionKey, uint32 passingAttestations, uint32 threshold);

    error AlreadyExists();
    error InvalidInput();
    error InvalidState();
    error InvalidIdentity();
    error SelfAttestation();

    constructor(address registryAddress, address admin, uint32 initialThreshold) {
        if (registryAddress == address(0) || registryAddress.code.length == 0 || admin == address(0)) {
            revert InvalidInput();
        }
        if (initialThreshold == 0 || initialThreshold > MAX_THRESHOLD) revert InvalidInput();
        registry = IDadiengRegistry(registryAddress);
        validatorThreshold = initialThreshold;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setValidatorIdentity(address validator, uint256 agentId, bool active)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (validator == address(0) || agentId == 0) revert InvalidInput();
        if (active) {
            address owner = agentIdOwners[agentId];
            if (owner != address(0) && owner != validator) revert InvalidIdentity();
            uint256 previousId = validatorAgentIds[validator];
            if (previousId != 0 && previousId != agentId) revert InvalidIdentity();
            validatorAgentIds[validator] = agentId;
            agentIdOwners[agentId] = validator;
            _grantRole(VALIDATOR_ROLE, validator);
        } else {
            if (validatorAgentIds[validator] != agentId || agentIdOwners[agentId] != validator) revert InvalidIdentity();
            delete validatorAgentIds[validator];
            delete agentIdOwners[agentId];
            _revokeRole(VALIDATOR_ROLE, validator);
        }
        emit ValidatorIdentitySet(validator, agentId, active);
    }

    function setValidatorThreshold(uint32 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold == 0 || newThreshold > MAX_THRESHOLD) revert InvalidInput();
        uint32 oldThreshold = validatorThreshold;
        validatorThreshold = newThreshold;
        emit ValidatorThresholdChanged(oldThreshold, newThreshold);
    }

    function submitAttestation(bytes32 versionKey, AttestationInput calldata input)
        external
        onlyRole(VALIDATOR_ROLE)
    {
        if (isValidationFinal[versionKey]) revert InvalidState();
        uint256 agentId = validatorAgentIds[msg.sender];
        if (agentId == 0 || agentIdOwners[agentId] != msg.sender) revert InvalidIdentity();

        (uint8 status, address author, uint256 authorAgentId, bool exists) =
            registry.getVersionValidationData(versionKey);
        if (!exists || status != CANDIDATE_STATUS) revert InvalidState();
        if (msg.sender == author || agentId == authorAgentId) revert SelfAttestation();
        if (_attestations[versionKey][agentId].createdAt != 0) revert AlreadyExists();
        if (
            input.reportHash == bytes32(0) || bytes(input.reportURI).length == 0 || input.attackTotal == 0
                || input.controlTotal == 0 || input.attackPassed > input.attackTotal
                || input.controlPassed > input.controlTotal
        ) revert InvalidInput();

        _attestations[versionKey][agentId] = Attestation({
            versionKey: versionKey,
            validatorAgentId: agentId,
            passed: input.passed,
            reportHash: input.reportHash,
            reportURI: input.reportURI,
            attackPassed: input.attackPassed,
            attackTotal: input.attackTotal,
            controlPassed: input.controlPassed,
            controlTotal: input.controlTotal,
            createdAt: uint64(block.timestamp),
            challenged: false
        });
        if (input.passed) passingAttestations[versionKey] += 1;
        emit AttestationSubmitted(versionKey, agentId, input.passed);
    }

    function challengeAttestation(bytes32 versionKey, uint256 validatorAgentId, bytes32 reasonCode, bytes32 evidenceHash)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        if (isValidationFinal[versionKey]) revert InvalidState();
        Attestation storage attestation = _attestations[versionKey][validatorAgentId];
        if (attestation.createdAt == 0 || attestation.challenged) revert InvalidState();
        if (reasonCode == bytes32(0) || evidenceHash == bytes32(0)) revert InvalidInput();
        attestation.challenged = true;
        if (attestation.passed) passingAttestations[versionKey] -= 1;
        emit AttestationChallenged(versionKey, validatorAgentId, reasonCode, evidenceHash);
    }

    function finalizeValidation(bytes32 versionKey) external {
        if (isValidationFinal[versionKey]) revert InvalidState();
        (uint8 status,,, bool exists) = registry.getVersionValidationData(versionKey);
        if (!exists || status != CANDIDATE_STATUS) revert InvalidState();
        uint32 count = passingAttestations[versionKey];
        uint32 threshold = validatorThreshold;
        if (count < threshold) revert InvalidState();
        isValidationFinal[versionKey] = true;
        emit ValidationFinalized(versionKey, count, threshold);
    }

    function getAttestation(bytes32 versionKey, uint256 validatorAgentId)
        external
        view
        returns (Attestation memory)
    {
        return _attestations[versionKey][validatorAgentId];
    }
}
