// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
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
    event SetToListMerkleRoot(bytes32 toListMerkleRoot);
    event SetTrustedToListMerkleRoot(bytes32 trustedToListMerkleRoot);
    event AddErc20List(address erc20Address);
    event DelErc20List(address erc20Address);
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
        address[] memory newSmallAmountTransfer,
        address newConfig,
        address newParam,
        string memory newPrefix,
        address[] memory newErc20List,
        bytes32 newToListMerkleRoot,
        bytes32 newTrustedToListMerkleRoot
    )
        AccessControlCustom(
            newAdmin,
            newSetter,
            newNoLimitTransfer,
            newSmallAmountTransfer
        )
    {
        _setErc20List(newErc20List);
        _setToListMerkleRoot(newToListMerkleRoot);
        _setTrustedToListMerkleRoot(newTrustedToListMerkleRoot);
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
     * @dev return merkle tree root of to list
     */
    function getToListMerkleRoot() external view returns (bytes32) {
        return VaultStorage.getVaultSlot()._toList;
    }

    /**
     * @dev return merkle tree root of trustedTo list
     */
    function getTrustedToListMerkleRoot() external view returns (bytes32) {
        return VaultStorage.getVaultSlot()._trustedToList;
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
     * @dev set merkle tree root of to list
     * @param newToListMerkleRoot - new merkle tree root of to list
     * @notice - Only SETTER_ROLE can call this function
     */
    function setToListMerkleRoot(bytes32 newToListMerkleRoot)
        external
        onlyRole(SETTER_ROLE)
    {
        _setToListMerkleRoot(newToListMerkleRoot);
    }

    /**
     * @dev set merkle tree root of trustedTo list
     * @param newTrustedToListMerkleRoot - new merkle tree root of trustedTo list
     * @notice - Only SETTER_ROLE can call this function
     */
    function setTrustedToListMerkleRoot(bytes32 newTrustedToListMerkleRoot)
        external
        onlyRole(SETTER_ROLE)
    {
        _setTrustedToListMerkleRoot(newTrustedToListMerkleRoot);
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
     * @dev delete address from erc20 list
     * @param erc20Address - erc20Address to be removed
     * @notice - Only SETTER_ROLE can call this function
     */
    function delErc20List(address erc20Address) external onlyRole(SETTER_ROLE) {
        _delErc20List(erc20Address);
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
     * @param toProof - the proof of toList
     * @param trustedToProof - the proof of trustedToList
     */
    function transfer(
        address to,
        address erc20,
        uint256 amount,
        string memory opcode,
        bytes32[] memory toProof,
        bytes32[] memory trustedToProof
    ) external {
        _transfer(to, erc20, amount, opcode, toProof, trustedToProof);
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
     * @dev set merkle tree root of to list
     * @param newToListMerkleRoot - new merkle tree root of to list
     */
    function _setToListMerkleRoot(bytes32 newToListMerkleRoot) internal {
        VaultStorage.getVaultSlot()._toList = newToListMerkleRoot;
        emit SetToListMerkleRoot(newToListMerkleRoot);
    }

    /**
     * @dev set merkle tree root of trustedTo list
     * @param newTrustedToListMerkleRoot - new merkle tree root of trustedTo list
     */
    function _setTrustedToListMerkleRoot(bytes32 newTrustedToListMerkleRoot)
        internal
    {
        VaultStorage.getVaultSlot()._trustedToList = newTrustedToListMerkleRoot;
        emit SetTrustedToListMerkleRoot(newTrustedToListMerkleRoot);
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
     * @dev delete address from erc20 list
     * @param erc20Address - erc20Address to be removed
     */
    function _delErc20List(address erc20Address) internal {
        VaultStorage.getVaultSlot()._erc20List.remove(erc20Address);
        emit DelErc20List(erc20Address);
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
        string memory opcode,
        bytes32[] memory toProof,
        bytes32[] memory trustedToProof
    ) internal {
        VaultStorage.VaultSlot storage data = VaultStorage.getVaultSlot();

        if (!data._erc20List.contains(erc20)) {
            revert(Errors.NOT_SUPPORTED_ERC20);
        }

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(to))));

        if (
            MerkleProof.verify(trustedToProof, data._trustedToList, leaf) ||
            hasRole(NO_LIMIT_TRANSFER_ROLE, _msgSender())
        ) {
            IERC20(erc20).safeTransfer(to, amount);
        } else if (hasRole(SMALL_AMOUNT_TRANSFER_ROLE, _msgSender())) {
            _smallAmountTransfer(to, erc20, amount, toProof);
            IERC20(erc20).safeTransfer(to, amount);
        } else {
            revert(Errors.FORBIDDEN);
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
        uint256 amount,
        bytes32[] memory toProof
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

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(to))));
        if (
            data._toList != bytes32(0) &&
            !MerkleProof.verify(toProof, data._toList, leaf)
        ) {
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
