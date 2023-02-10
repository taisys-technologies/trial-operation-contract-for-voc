// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

library SettingStorage {
    struct UintStruct {
        uint256 value;
        bool status;
    }

    struct AddressStruct {
        address value;
        bool status;
    }

    struct SettingSlot {
        // uint mapping
        mapping(address => mapping(bytes32 => UintStruct)) _uintMap;
        // address mapping
        mapping(address => mapping(bytes32 => AddressStruct)) _addressMap;
    }

    bytes32 internal constant SLOT_KEY_Setting =
        keccak256("Setting.storages.Setting");

    function getSettingSlot() internal pure returns (SettingSlot storage l) {
        bytes32 slot = SLOT_KEY_Setting;
        assembly {
            l.slot := slot
        }
    }
}
