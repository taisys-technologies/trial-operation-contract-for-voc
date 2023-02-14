// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISetting {
    struct UintStruct {
        uint256 value;
        bool status;
    }

    function checkUint(address wallet, string memory key)
        external
        view
        returns (UintStruct memory);
}
