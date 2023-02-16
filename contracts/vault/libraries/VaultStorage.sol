// SPDX-License-Identifier: MIT

pragma solidity 0.8.12;

import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

library VaultStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    uint256 constant _WHITELISTLENGTH = 20;
    uint256 constant MAX_INT_TYPE = type(uint256).max;

    struct VaultSlot {
        string _prefix;
        address _config;
        address _param;
        EnumerableSet.AddressSet _erc20List;
        bytes32 _toList;
        bytes32 _trustedToList;
        mapping(address => mapping(uint256 => uint256)) _amountRecords;
        mapping(address => mapping(uint256 => uint256)) _frequencyRecords;
    }

    bytes32 internal constant SLOT_KEY_Vault =
        keccak256("Vault.storages.Vault");

    function getVaultSlot() internal pure returns (VaultSlot storage l) {
        bytes32 slot = SLOT_KEY_Vault;
        assembly {
            l.slot := slot
        }
    }
}
