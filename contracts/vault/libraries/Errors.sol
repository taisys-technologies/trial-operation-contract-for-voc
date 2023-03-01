// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

library Errors {
    // common
    string internal constant ZERO_ADDRESS = "Vault_001";
    // Vault errors
    string internal constant LIST_TO_LONG = "Vault_101";
    string internal constant DUPLICATED_ADDRESS = "Vault_102";
    string internal constant NOT_SUPPORTED_ERC20 = "Vault_103";
    string internal constant INVALID_TRANSFER = "Vault_104";
    string internal constant INVALID_TO_ADDRESS = "Vault_105";
    string internal constant OVER_MAX_AMOUNT_PER_COUNT = "Vault_106";
    string internal constant OVER_MAX_AMOUNT_PER_DAY = "Vault_107";
    string internal constant OVER_MAX_COUNT_PER_DAY = "Vault_108";
    string internal constant LIST_EXCEED_LENGTH_LIMIT = "Vault_109";
    string internal constant FORBIDDEN = "Vault_110";
    // Vault AccessControl errors
    string internal constant NOT_IN_TRANSITION = "Vault_201";
    string internal constant ALREADY_IN_TRANSITION = "Vault_202";
    string internal constant GRANT_ROLE_INVALID_ADDRESS = "Vault_203";
    string internal constant INVALID_TRANSITION = "Vault_204";
}
