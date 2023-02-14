// SPDX-License-Identifier: MIT

pragma solidity 0.8.12;

library SettingStorage {
    struct IntStruct {
        int256 value;
        bool status;
    }

    struct UintStruct {
        uint256 value;
        bool status;
    }

    struct AddressStruct {
        address value;
        bool status;
    }

    struct StringStruct {
        string value;
        bool status;
    }

    struct DataStruct {
        bytes value;
        bool status;
    }

    struct SettingSlot {
        mapping(address => mapping(bytes32 => DataStruct)) _dataMap;
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
