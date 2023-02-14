// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./AccessControlCustom.sol";
import "./libraries/VaultStorage.sol";
import "./interfaces/ISetting.sol";

contract Vault is AccessControlCustom, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using VaultStorage for VaultStorage.VaultSlot;
    using EnumerableSet for EnumerableSet.AddressSet;

    struct Status {
        uint256 amount;
        uint256 frequency;
    }

    /**********
     * Events *
     **********/

    event SetErc20List(address[] erc20AddressList);
    event SetToList(address[] toAddressList);
    event SetTrustedToList(address[] trustedToAddressList);
    event AddErc20List(address erc20Address);
    event AddToList(address toAddress);
    event AddTrustedToList(address trustedToAddress);
    event DelErc20List(address erc20Address);
    event DelToList(address toAddress);
    event DelTrustedToToList(address trustedToAddress);
    event SetConfigAddress(address config);
    event SetParamAddress(address param);
    event Transfer(address to, address erc20, uint256 amount, string opcode);

    /***************
     * Constructor *
     ***************/

    constructor(
        address newAdmin,
        address[] memory newSetter,
        address[] memory newNoLimitTransfer,
        address newConfig,
        address newParam,
        string memory newPrefix,
        address[] memory newErc20List,
        address[] memory newToList,
        address[] memory newTrustedToList
    ) AccessControlCustom(newAdmin, newSetter, newNoLimitTransfer) {
        _setErc20List(newErc20List);
        _setToList(newToList);
        _setTrustedToList(newTrustedToList);
        _setConfigAddress(newConfig);
        _setParamAddress(newParam);
        VaultStorage.getVaultSlot()._prefix = newPrefix;
    }

    /**********************
     * External Functions *
     **********************/

    /**
     * @dev return prefix
     */
    function prefix() external view returns (string memory) {
        return VaultStorage.getVaultSlot()._prefix;
    }

    /**
     * @dev return config address
     */
    function config() external view returns (address) {
        return VaultStorage.getVaultSlot()._config;
    }

    /**
     * @dev return param address
     */
    function param() external view returns (address) {
        return VaultStorage.getVaultSlot()._param;
    }

    /**
     * @dev return wallet currently available amount and frequency
     * @param wallet - wallet to be checked
     * @param erc20 - erc20 to be checked
     * @param timestamp - time need to be checked
     * @notice - If there is no limitation, then return max uint256
     */
    function getStatus(
        address wallet,
        address erc20,
        uint256 timestamp
    ) external view returns (Status memory) {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();
        ISetting.UintStruct memory maxAmountPerDay = _getMaxAmountPerDay(erc20);
        ISetting.UintStruct memory maxCountPerDay = _getMaxCountPerDay(erc20);
        uint256 availableAmount;
        uint256 availableFrequency;

        // get wallet currently records
        uint256 currentAmount = data._amountRecords[wallet][timestamp / 1 days];
        uint256 currentFrequency = data._frequencyRecords[wallet][
            timestamp / 1 days
        ];

        if (maxAmountPerDay.status && currentAmount < maxAmountPerDay.value) {
            availableAmount = maxAmountPerDay.value - currentAmount;
        }
        if (!maxAmountPerDay.status) {
            availableAmount = VaultStorage.MAX_INT_TYPE;
        }

        if (maxCountPerDay.status && currentFrequency < maxCountPerDay.value) {
            availableFrequency = maxCountPerDay.value - currentFrequency;
        }
        if (!maxCountPerDay.status) {
            availableFrequency = VaultStorage.MAX_INT_TYPE;
        }

        return Status({amount: availableAmount, frequency: availableFrequency});
    }

    /**
     * @dev return erc20 list
     */
    function getErc20List() external view returns (address[] memory) {
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._erc20List;
        uint256 length = data.length();
        address[] memory res = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            res[i] = data.at(i);
        }
        return res;
    }

    /**
     * @dev return to list
     */
    function getToList() external view returns (address[] memory) {
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._toList;
        uint256 length = data.length();
        address[] memory res = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            res[i] = data.at(i);
        }
        return res;
    }

    /**
     * @dev return trustedTo list
     */
    function getTrustedToList() external view returns (address[] memory) {
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._trustedToList;
        uint256 length = data.length();
        address[] memory res = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            res[i] = data.at(i);
        }
        return res;
    }

    /**
     * @dev set address list to erc20 list
     * @param newErc20AddressList - new erc20 address list
     * @notice - Only SETTER_ROLE can call this function
     */
    function setErc20List(address[] memory newErc20AddressList)
        external
        onlyRole(SETTER_ROLE)
    {
        _setErc20List(newErc20AddressList);
    }

    /**
     * @dev set address list to to list
     * @param newToAddressList - new to address list
     * @notice - Only SETTER_ROLE can call this function
     */
    function setToList(address[] memory newToAddressList)
        external
        onlyRole(SETTER_ROLE)
    {
        _setToList(newToAddressList);
    }

    /**
     * @dev set address list to trustedTo list
     * @param newTrustedToAddressList - new trustedTo address list
     * @notice - Only SETTER_ROLE can call this function
     */
    function setTrustedToList(address[] memory newTrustedToAddressList)
        external
        onlyRole(SETTER_ROLE)
    {
        _setTrustedToList(newTrustedToAddressList);
    }

    /**
     * @dev add address to erc20 list
     * @param newErc20Address - new erc20 address
     * @notice - Only SETTER_ROLE can call this function
     */
    function addErc20List(address newErc20Address)
        external
        onlyRole(SETTER_ROLE)
    {
        _addErc20List(newErc20Address);
    }

    /**
     * @dev add address to to list
     * @param newToAddress - new to address
     * @notice - Only SETTER_ROLE can call this function
     */
    function addToList(address newToAddress) external onlyRole(SETTER_ROLE) {
        _addToList(newToAddress);
    }

    /**
     * @dev add address to trustedTo list
     * @param newTrustedToList - new trustedTo address
     * @notice - Only SETTER_ROLE can call this function
     */
    function addTrustedToList(address newTrustedToList)
        external
        onlyRole(SETTER_ROLE)
    {
        _addTrustedToList(newTrustedToList);
    }

    /**
     * @dev delete address from erc20 list
     * @param erc20Address - erc20Address to be removed
     * @notice - Only SETTER_ROLE can call this function
     */
    function delErc20List(address erc20Address) external onlyRole(SETTER_ROLE) {
        _delErc20List(erc20Address);
    }

    /**
     * @dev delete address from to list
     * @param toAddress - toAddress to be removed
     * @notice - Only SETTER_ROLE can call this function
     */
    function delToList(address toAddress) external onlyRole(SETTER_ROLE) {
        _delToList(toAddress);
    }

    /**
     * @dev delete address from trustedTo list
     * @param trustedToAddress - trustedToAddress to be removed
     * @notice - Only SETTER_ROLE can call this function
     */
    function delTrustedToList(address trustedToAddress)
        external
        onlyRole(SETTER_ROLE)
    {
        _delTrustedToList(trustedToAddress);
    }

    /**
     * @dev set config
     * @param newConfig - new config address
     * @notice - Only SETTER_ROLE can call this function
     */
    function setConfigAddress(address newConfig)
        external
        onlyRole(SETTER_ROLE)
    {
        _setConfigAddress(newConfig);
    }

    /**
     * @dev set param
     * @param newParam - new param address
     * @notice - Only SETTER_ROLE can call this function
     */
    function setParamAddress(address newParam) external onlyRole(SETTER_ROLE) {
        _setParamAddress(newParam);
    }

    /**
     * @dev transfer specific erc20 from this contract
     * @param to - the address that erc20 transfer to
     * @param erc20 - the token of transfer
     * @param amount - the amount of transfer
     * @param opcode - the opcode of transfer
     */
    function transfer(
        address to,
        address erc20,
        uint256 amount,
        string memory opcode
    ) external {
        _transfer(to, erc20, amount, opcode);
    }

    /**********************
     * Internal Functions *
     **********************/

    /**
     * @dev return key of max amount per count with specific info
     * @param erc20 - erc20 address to be checked
     */
    function _getMaxAmountPerCount(address erc20)
        internal
        view
        returns (ISetting.UintStruct memory)
    {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();
        return
            ISetting(data._config).checkUint(
                data._param,
                _concatKey(data._prefix, erc20, "max_amount_per_count")
            );
    }

    /**
     * @dev return key of max amount per day with specific info
     * @param erc20 - erc20 address to be checked
     */
    function _getMaxAmountPerDay(address erc20)
        internal
        view
        returns (ISetting.UintStruct memory)
    {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();
        return
            ISetting(data._config).checkUint(
                data._param,
                _concatKey(data._prefix, erc20, "max_amount_per_day")
            );
    }

    /**
     * @dev return key of max count per day with specific info
     * @param erc20 - erc20 address to be checked
     */
    function _getMaxCountPerDay(address erc20)
        internal
        view
        returns (ISetting.UintStruct memory)
    {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();
        return
            ISetting(data._config).checkUint(
                data._param,
                _concatKey(data._prefix, erc20, "max_count_per_day")
            );
    }

    /**
     * @dev return key of large amount with specific info
     * @param erc20 - erc20 address to be checked
     */
    function _getLargeAmount(address erc20)
        internal
        view
        returns (ISetting.UintStruct memory)
    {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();
        return
            ISetting(data._config).checkUint(
                data._param,
                _concatKey(data._prefix, erc20, "large_amount")
            );
    }

    /**
     * @dev return string after concat
     * @param prefixString - prefix string
     * @param erc20 - erc20 address
     * @param key - string of main data
     */
    function _concatKey(
        string memory prefixString,
        address erc20,
        string memory key
    ) internal pure returns (string memory) {
        return
            string.concat(
                prefixString,
                "_",
                Strings.toHexString(erc20),
                "_",
                key
            );
    }

    /**
     * @dev set address list to erc20 list
     * @param newErc20AddressList - new erc20 address list
     */
    function _setErc20List(address[] memory newErc20AddressList) internal {
        if (newErc20AddressList.length > VaultStorage._WHITELISTLENGTH) {
            revert(Errors.LIST_TO_LONG);
        }
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._erc20List;
        uint256 length = data.length();

        if (length > 0) {
            // delete old data
            for (uint256 i = length; i > 0; i--) {
                _delErc20List(data.at(i - 1));
            }
        }

        // set new data
        for (uint256 i = 0; i < newErc20AddressList.length; i++) {
            _addErc20List(newErc20AddressList[i]);
        }
        emit SetErc20List(newErc20AddressList);
    }

    /**
     * @dev set address list to to list
     * @param newToAddressList - new to address list
     */
    function _setToList(address[] memory newToAddressList) internal {
        if (newToAddressList.length > VaultStorage._WHITELISTLENGTH) {
            revert(Errors.LIST_TO_LONG);
        }
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._toList;
        uint256 length = data.length();

        if (length > 0) {
            // delete old data
            for (uint256 i = length; i > 0; i--) {
                _delToList(data.at(i - 1));
            }
        }

        // set new data
        for (uint256 i = 0; i < newToAddressList.length; i++) {
            _addToList(newToAddressList[i]);
        }
        emit SetToList(newToAddressList);
    }

    /**
     * @dev set address list to trustedTo list
     * @param newTrustedToAddressList - new trustedTo address list
     */
    function _setTrustedToList(address[] memory newTrustedToAddressList)
        internal
    {
        if (newTrustedToAddressList.length > VaultStorage._WHITELISTLENGTH) {
            revert(Errors.LIST_TO_LONG);
        }
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._trustedToList;
        uint256 length = data.length();

        if (length > 0) {
            // delete old data
            for (uint256 i = length; i > 0; i--) {
                _delTrustedToList(data.at(i - 1));
            }
        }

        // set new data
        for (uint256 i = 0; i < newTrustedToAddressList.length; i++) {
            _addTrustedToList(newTrustedToAddressList[i]);
        }
        emit SetTrustedToList(newTrustedToAddressList);
    }

    /**
     * @dev add address to erc20 list
     * @param newErc20Address - new erc20 address
     */
    function _addErc20List(address newErc20Address) internal {
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._erc20List;
        if (newErc20Address == address(0)) {
            revert(Errors.ZERO_ADDRESS);
        }
        if (data.contains(newErc20Address)) {
            revert(Errors.DUPLICATED_ADDRESS);
        }
        if (data.length() >= VaultStorage._WHITELISTLENGTH) {
            revert(Errors.LIST_EXCEED_LENGTH_LIMIT);
        }
        data.add(newErc20Address);
        emit AddErc20List(newErc20Address);
    }

    /**
     * @dev add address to to list
     * @param newToAddress - new to address
     */
    function _addToList(address newToAddress) internal {
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._toList;
        if (newToAddress == address(0)) {
            revert(Errors.ZERO_ADDRESS);
        }
        if (data.contains(newToAddress)) {
            revert(Errors.DUPLICATED_ADDRESS);
        }
        if (data.length() >= VaultStorage._WHITELISTLENGTH) {
            revert(Errors.LIST_EXCEED_LENGTH_LIMIT);
        }
        data.add(newToAddress);
        emit AddToList(newToAddress);
    }

    /**
     * @dev add address to trustedTo list
     * @param newTrustedToList - new trustedTo address
     */
    function _addTrustedToList(address newTrustedToList) internal {
        EnumerableSet.AddressSet storage data = VaultStorage
            .getVaultSlot()
            ._trustedToList;
        if (newTrustedToList == address(0)) {
            revert(Errors.ZERO_ADDRESS);
        }
        if (data.contains(newTrustedToList)) {
            revert(Errors.DUPLICATED_ADDRESS);
        }
        if (data.length() >= VaultStorage._WHITELISTLENGTH) {
            revert(Errors.LIST_EXCEED_LENGTH_LIMIT);
        }
        data.add(newTrustedToList);
        emit AddTrustedToList(newTrustedToList);
    }

    /**
     * @dev delete address from erc20 list
     * @param erc20Address - erc20Address to be removed
     */
    function _delErc20List(address erc20Address) internal {
        VaultStorage.getVaultSlot()._erc20List.remove(erc20Address);
        emit DelErc20List(erc20Address);
    }

    /**
     * @dev delete address from to list
     * @param toAddress - toAddress to be removed
     */
    function _delToList(address toAddress) internal {
        VaultStorage.getVaultSlot()._toList.remove(toAddress);
        emit DelToList(toAddress);
    }

    /**
     * @dev delete address from trustedTo list
     * @param trustedToAddress - trustedToAddress to be removed
     */
    function _delTrustedToList(address trustedToAddress) internal {
        VaultStorage.getVaultSlot()._trustedToList.remove(trustedToAddress);
        emit DelTrustedToToList(trustedToAddress);
    }

    /**
     * @dev set config
     * @param newConfig - new config address
     */
    function _setConfigAddress(address newConfig) internal {
        if (newConfig == address(0)) {
            revert(Errors.ZERO_ADDRESS);
        }
        VaultStorage.getVaultSlot()._config = newConfig;
        emit SetConfigAddress(newConfig);
    }

    /**
     * @dev set param
     * @param newParam - new param address
     */
    function _setParamAddress(address newParam) internal {
        if (newParam == address(0)) {
            revert(Errors.ZERO_ADDRESS);
        }
        VaultStorage.getVaultSlot()._param = newParam;
        emit SetParamAddress(newParam);
    }

    /**
     * @dev transfer specific erc20 from this contract
     * @param to - the address that erc20 transfer to
     * @param erc20 - the token of transfer
     * @param amount - the amount of transfer
     * @param opcode - the opcode of transfer
     */
    function _transfer(
        address to,
        address erc20,
        uint256 amount,
        string memory opcode
    ) internal {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();

        if (!data._erc20List.contains(erc20)) {
            revert(Errors.NOT_SUPPORTED_ERC20);
        }

        if (
            data._trustedToList.contains(to) ||
            hasRole(NO_LIMIT_TRANSFER_ROLE, _msgSender())
        ) {
            IERC20(erc20).safeTransfer(to, amount);
        } else {
            _smallAmountTransfer(to, erc20, amount);
            IERC20(erc20).safeTransfer(to, amount);
        }

        emit Transfer(to, erc20, amount, opcode);
    }

    /**
     * @dev check small amount transfer is valid
     * @param to - the address that erc20 transfer to
     * @param erc20 - the token of transfer
     * @param amount - the amount of transfer
     */
    function _smallAmountTransfer(
        address to,
        address erc20,
        uint256 amount
    ) internal {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();
        ISetting.UintStruct memory maxAmountPerCount = _getMaxAmountPerCount(
            erc20
        );
        ISetting.UintStruct memory maxAmountPerDay = _getMaxAmountPerDay(erc20);
        ISetting.UintStruct memory maxCountPerDay = _getMaxCountPerDay(erc20);
        ISetting.UintStruct memory largeAmount = _getLargeAmount(erc20);
        uint256 current = block.timestamp;

        // get wallet currently record
        uint256 currentAmount = data._amountRecords[to][current / 1 days];
        uint256 currentFrequency = data._frequencyRecords[to][current / 1 days];

        // check if amount is smaller than large_amount
        // if large_amount not exist, than it's equal to 0
        if (!largeAmount.status || largeAmount.value <= amount) {
            revert(Errors.INVALID_TRANSFER);
        }

        if (!data._toList.contains(to) && data._toList.length() != 0) {
            revert(Errors.INVALID_TO_ADDRESS);
        }

        // checked amount and frequency by limitation
        if (amount > maxAmountPerCount.value && maxAmountPerCount.status) {
            revert(Errors.OVER_MAX_AMOUNT_PER_COUNT);
        }
        if (
            currentAmount + amount > maxAmountPerDay.value &&
            maxAmountPerDay.status
        ) {
            revert(Errors.OVER_MAX_AMOUNT_PER_DAY);
        }
        if (
            currentFrequency + 1 > maxCountPerDay.value && maxCountPerDay.status
        ) {
            revert(Errors.OVER_MAX_COUNT_PER_DAY);
        }

        // update record
        data._amountRecords[to][current / 1 days] += amount;
        data._frequencyRecords[to][current / 1 days] += 1;
    }
}
