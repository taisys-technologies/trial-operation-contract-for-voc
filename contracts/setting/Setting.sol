// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

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
    event DelUint(address wallet, string key);
    event SetAddress(address wallet, string key, address value);
    event DelAddress(address wallet, string key);

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
     * @dev return the value of specific wallet and corresponding key(Uint Mapping)
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function getUint(address wallet, string memory key)
        external
        view
        returns (uint256)
    {
        return
            SettingStorage
            .getSettingSlot()
            ._uintMap[wallet][keccak256(bytes(key))].value;
    }

    /**
     * @dev return the status of specific wallet and corresponding key(Uint Mapping)
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function availableUint(address wallet, string memory key)
        external
        view
        returns (bool)
    {
        return
            SettingStorage
            .getSettingSlot()
            ._uintMap[wallet][keccak256(bytes(key))].status;
    }

    /**
     * @dev return competed data of specific wallet and corresponding key(Uint Mapping)
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function checkUint(address wallet, string memory key)
        external
        view
        returns (SettingStorage.UintStruct memory)
    {
        return
            SettingStorage.getSettingSlot()._uintMap[wallet][
                keccak256(bytes(key))
            ];
    }

    /**
     * @dev return the value of specific wallet and corresponding key(Address Mapping)
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function getAddress(address wallet, string memory key)
        external
        view
        returns (address)
    {
        return
            SettingStorage
            .getSettingSlot()
            ._addressMap[wallet][keccak256(bytes(key))].value;
    }

    /**
     * @dev return the status of specific wallet and corresponding key(Address Mapping)
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function availableAddress(address wallet, string memory key)
        external
        view
        returns (bool)
    {
        return
            SettingStorage
            .getSettingSlot()
            ._addressMap[wallet][keccak256(bytes(key))].status;
    }

    /**
     * @dev return completed value of specific wallet and corresponding key(Address Mapping)
     * @param wallet - address to be  searched
     * @param key - key to be  searched
     */
    function checkAddress(address wallet, string memory key)
        external
        view
        returns (SettingStorage.AddressStruct memory)
    {
        return
            SettingStorage.getSettingSlot()._addressMap[wallet][
                keccak256(bytes(key))
            ];
    }

    /**
     * @dev set new value to specific wallet and corresponding key(Uint Mapping)
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
        data._uintMap[wallet][keccak256(bytes(key))].value = value;
        data._uintMap[wallet][keccak256(bytes(key))].status = true;

        emit SetUint(wallet, key, value);
    }

    /**
     * @dev delete value of specific wallet and corresponding key(Uint Mapping)
     * @param wallet - address to be deleted
     * @param key - key to be deleted
     */
    function delUint(address wallet, string memory key) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );

        SettingStorage
        .getSettingSlot()
        ._uintMap[wallet][keccak256(bytes(key))].status = false;

        emit DelUint(wallet, key);
    }

    /**
     * @dev set new value to specific wallet and corresponding key(Address Mapping)
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
        data._addressMap[wallet][keccak256(bytes(key))].value = value;
        data._addressMap[wallet][keccak256(bytes(key))].status = true;

        emit SetAddress(wallet, key, value);
    }

    /**
     * @dev delete value of specific wallet and corresponding key(Address Mapping)
     * @param wallet - address to be deleted
     * @param key - key to be deleted
     */
    function delAddress(address wallet, string memory key) external {
        require(
            hasRole(SETTER_ROLE, _msgSender()) || wallet == _msgSender(),
            Errors.FORBIDDEN
        );

        SettingStorage
        .getSettingSlot()
        ._addressMap[wallet][keccak256(bytes(key))].status = false;

        emit DelAddress(wallet, key);
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
