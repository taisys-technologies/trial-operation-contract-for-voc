// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

library Errors {
    // common
    string internal constant ZERO_ADDRESS = "Setting_001";
    // Setting errors
    string internal constant FORBIDDEN = "Setting_101";
    // Setting AccessControl errors
    string internal constant NOT_IN_TRANSITION = "Setting_201";
    string internal constant ALREADY_IN_TRANSITION = "Setting_202";
    string internal constant GRANT_ROLE_INVALID_ADDRESS = "Setting_203";
    string internal constant INVALID_TRANSITION = "Setting_204";
}
