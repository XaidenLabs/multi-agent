// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IDadiengRegistry {
    function getVersionValidationData(bytes32 versionKey)
        external
        view
        returns (uint8 status, address author, uint256 authorAgentId, bool exists);
}

interface IDadiengValidation {
    function isValidationFinal(bytes32 versionKey) external view returns (bool);
}
