// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import {SettingStorage} from "./libraries/SettingStorage.sol";
import "./AccessControlUpgradeableCustom.sol";

contract Setting is
    AccessControlUpgradeableCustom,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SettingStorage for SettingStorage.SettingSlot;

    /*********
     * Event *
     *********/

    event SetUint(address wallet, string key, uint256 value);
    event SetAddress(address wallet, string key, address value);
    event SetString(address wallet, string key, string value);
    event SetInt(address wallet, string key, int256 value);
    event SetBytes(address wallet, string key, bytes value);
    event Del(address wallet, string key);

    /**************
     * Initialize *
     ***************/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address newAdmin, address[] memory newSetters)
        public
        initializer
    {
        __AccessControlCustom_init(newAdmin, newSetters);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
    }

    /**********************
     * External Functions *
     **********************/

    /**
     * @dev return the status of specific wallet and corresponding key
     * @param wallet - address to be searched
     * @param key - key to be  searched
     */
    function available(address wallet, string memory key)
        external
        view
        returns (bool)
    {
        return
            SettingStorage
            .getSettingSlot()
            ._dataMap[wallet][keccak256(bytes(key))].status;
    }

    /**
     * @dev return uint256 from dataMap
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function getUint(address wallet, string memory key)
        external
        view
        returns (uint256)
    {
        return
            uint256(
                bytes32(
                    SettingStorage
                    .getSettingSlot()
                    ._dataMap[wallet][keccak256(bytes(key))].value
                )
            );
    }

    /**
     * @dev return completed data (Uint)
     * @param wallet - address to be searched
     * @param key - key to be searched
     */
    function checkUint(address wallet, string memory key)
        external
        view
        returns (SettingStorage.UintStruct memory)
    {
        SettingStorage.DataStruct storage data = SettingStorage
            .getSettingSlot()
            ._dataMap[wallet][keccak256(bytes(key))];
        return
            SettingStorage.UintStruct({
                value: uint256(bytes32(data.value)),
                status: data.status
            });
    }

    /**
     * @dev return address from dataMap
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function getAddress(address wallet, string memory key)
        external
        view
        returns (address)
    {
        return
            address(
                bytes20(
                    SettingStorage
                    .getSettingSlot()
                    ._dataMap[wallet][keccak256(bytes(key))].value
                )
            );
    }

    /**
     * @dev return completed data (Address)
     * @param wallet - address to be searched
     * @param key - key to be searched
     */
    function checkAddress(address wallet, string memory key)
        external
        view
        returns (SettingStorage.AddressStruct memory)
    {
        SettingStorage.DataStruct storage data = SettingStorage
            .getSettingSlot()
            ._dataMap[wallet][keccak256(bytes(key))];
        return
            SettingStorage.AddressStruct({
                value: address(bytes20(data.value)),
                status: data.status
            });
    }

    /**
     * @dev return string from dataMap
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function getString(address wallet, string memory key)
        external
        view
        returns (string memory)
    {
        return
            string(
                SettingStorage
                .getSettingSlot()
                ._dataMap[wallet][keccak256(bytes(key))].value
            );
    }

    /**
     * @dev return completed data (string)
     * @param wallet - address to be searched
     * @param key - key to be searched
     */
    function checkString(address wallet, string memory key)
        external
        view
        returns (SettingStorage.StringStruct memory)
    {
        SettingStorage.DataStruct storage data = SettingStorage
            .getSettingSlot()
            ._dataMap[wallet][keccak256(bytes(key))];
        return
            SettingStorage.StringStruct({
                value: string(data.value),
                status: data.status
            });
    }

    /**
     * @dev return int256 from dataMap
     * @param wallet - address to be searched
     * @param key - key to be  searched
     */
    function getInt(address wallet, string memory key)
        external
        view
        returns (int256)
    {
        return
            int256(
                uint256(
                    bytes32(
                        SettingStorage
                        .getSettingSlot()
                        ._dataMap[wallet][keccak256(bytes(key))].value
                    )
                )
            );
    }

    /**
     * @dev return completed data (int)
     * @param wallet - address to be searched
     * @param key - key to be searched
     */
    function checkInt(address wallet, string memory key)
        external
        view
        returns (SettingStorage.IntStruct memory)
    {
        SettingStorage.DataStruct storage data = SettingStorage
            .getSettingSlot()
            ._dataMap[wallet][keccak256(bytes(key))];
        return
            SettingStorage.IntStruct({
                value: int256(uint256(bytes32(data.value))),
                status: data.status
            });
    }

    /**
     * @dev return bytes from dataMap
     * @param wallet - address to be searched
     * @param key - key to be  searched
     */
    function getBytes(address wallet, string memory key)
        external
        view
        returns (bytes memory)
    {
        return
            SettingStorage
            .getSettingSlot()
            ._dataMap[wallet][keccak256(bytes(key))].value;
    }

    /**
     * @dev return completed data (bytes)
     * @param wallet - address to be searched
     * @param key - key to be searched
     */
    function checkBytes(address wallet, string memory key)
        external
        view
        returns (SettingStorage.DataStruct memory)
    {
        return
            SettingStorage.getSettingSlot()._dataMap[wallet][
                keccak256(bytes(key))
            ];
    }

    /**
     * @dev delete value of specific wallet and corresponding key
     * @param wallet - address to be deleted
     * @param key - key to be deleted
     */
    function del(address wallet, string memory key) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );

        SettingStorage
        .getSettingSlot()
        ._dataMap[wallet][keccak256(bytes(key))].status = false;

        emit Del(wallet, key);
    }

    /**
     * @dev set new uint256 to specific wallet and corresponding key
     * @param wallet - address to be setted
     * @param key - key to be setted
     * @param value - new value
     */
    function setUint(
        address wallet,
        string memory key,
        uint256 value
    ) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );
        SettingStorage.SettingSlot storage data = SettingStorage
            .getSettingSlot();
        data._dataMap[wallet][keccak256(bytes(key))].value = abi.encodePacked(
            value
        );
        data._dataMap[wallet][keccak256(bytes(key))].status = true;

        emit SetUint(wallet, key, value);
    }

    /**
     * @dev set new address to specific wallet and corresponding key
     * @param wallet - address to be setted
     * @param key - key to be setted
     * @param value - new value
     */
    function setAddress(
        address wallet,
        string memory key,
        address value
    ) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );
        SettingStorage.SettingSlot storage data = SettingStorage
            .getSettingSlot();
        data._dataMap[wallet][keccak256(bytes(key))].value = abi.encodePacked(
            value
        );
        data._dataMap[wallet][keccak256(bytes(key))].status = true;

        emit SetAddress(wallet, key, value);
    }

    /**
     * @dev set new string to specific wallet and corresponding key
     * @param wallet - address to be setted
     * @param key - key to be setted
     * @param value - new value
     */
    function setString(
        address wallet,
        string memory key,
        string memory value
    ) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );
        SettingStorage.SettingSlot storage data = SettingStorage
            .getSettingSlot();
        data._dataMap[wallet][keccak256(bytes(key))].value = bytes(value);
        data._dataMap[wallet][keccak256(bytes(key))].status = true;

        emit SetString(wallet, key, value);
    }

    /**
     * @dev set new int256 to specific wallet and corresponding key
     * @param wallet - address to be setted
     * @param key - key to be setted
     * @param value - new value
     */
    function setInt(
        address wallet,
        string memory key,
        int256 value
    ) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );
        SettingStorage.SettingSlot storage data = SettingStorage
            .getSettingSlot();
        data._dataMap[wallet][keccak256(bytes(key))].value = abi.encodePacked(
            value
        );
        data._dataMap[wallet][keccak256(bytes(key))].status = true;

        emit SetInt(wallet, key, value);
    }

    /**
     * @dev set new bytes to specific wallet and corresponding key
     * @param wallet - address to be setted
     * @param key - key to be setted
     * @param value - new value
     */
    function setBytes(
        address wallet,
        string memory key,
        bytes memory value
    ) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );
        SettingStorage.SettingSlot storage data = SettingStorage
            .getSettingSlot();
        data._dataMap[wallet][keccak256(bytes(key))].value = value;
        data._dataMap[wallet][keccak256(bytes(key))].status = true;

        emit SetBytes(wallet, key, value);
    }

    /**********************
     * Internal Functions *
     **********************/

    // The following functions are overrides required by Solidity.
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}
}
