// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import {Errors} from "./libraries/Errors.sol";

contract AccessControlCustom is AccessControlEnumerable {
    using Address for address;

    /**
     * Global Variables
     */
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");
    bytes32 public constant NO_LIMIT_TRANSFER_ROLE =
        keccak256("NO_LIMIT_TRANSFER_ROLE");
    bytes32 public constant SMALL_AMOUNT_TRANSFER_ROLE =
        keccak256("SMALL_AMOUNT_TRANSFER_ROLE");
    // record pending transition
    mapping(address => address) private _inTransition;

    /**
     * Events
     */

    event TransferAdmin(address adminAddress);
    event UpdateAdmin(address oldAdminAddress);
    event CancelTransferAdmin(address newAdminAddress);

    /**
     * Modifier
     */

    /**
     * @dev Modifier to make a function callable only when the transition exist.
     *
     * Requirements:
     *
     * - The transition must exist.
     */
    modifier inTransition(address oldAdmin) {
        if (_inTransition[oldAdmin] == address(0)) {
            revert(Errors.NOT_IN_TRANSITION);
        }
        _;
    }

    /**
     * @dev Modifier to make a function callable only when there's no transition pending.
     *
     * Requirements:
     *
     * - No transition is pending.
     */
    modifier notInTransition() {
        if (_inTransition[_msgSender()] != address(0)) {
            revert(Errors.ALREADY_IN_TRANSITION);
        }
        _;
    }

    /**
     * Constructor
     */

    constructor(
        address newAdmin,
        address[] memory newSetter,
        address[] memory newNoLimitTransfer,
        address[] memory newSmallAmountTransfer
    ) {
        if (newAdmin == address(0)) {
            revert(Errors.ZERO_ADDRESS);
        }

        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _setRoleAdmin(SETTER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(NO_LIMIT_TRANSFER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(SMALL_AMOUNT_TRANSFER_ROLE, ADMIN_ROLE);

        _grantRole(ADMIN_ROLE, newAdmin);
        _batchGrantSetter(newSetter);
        _batchGrantNoLimitTransfer(newNoLimitTransfer);
        _batchGrantSmallAmountTransfer(newSmallAmountTransfer);
    }

    /**
     * Functions
     */

    /**
     * @dev return whom the Admin role is transfered to
     * @param admin address - the original Admin
     */
    function transition(address admin) external view returns (address) {
        return _inTransition[admin];
    }

    /**
     * @dev grant admin to newAdmin, and set a pending transition in record
     * @param newAdmin address - the address that Admin role is transfered to
     * @notice - Only Admin can call this function.
     */
    function transferAdmin(address newAdmin)
        external
        onlyRole(ADMIN_ROLE)
        notInTransition
    {
        if (newAdmin == address(0) || newAdmin == _msgSender()) {
            revert(Errors.GRANT_ROLE_INVALID_ADDRESS);
        }
        _inTransition[_msgSender()] = newAdmin;
        emit TransferAdmin(newAdmin);
    }

    /**
     * @dev the address who gets admin from transition are able to accept and revoke the old Admin
     * @param oldAdmin address - the original Admin address
     */
    function updateAdmin(address oldAdmin) external inTransition(oldAdmin) {
        if (_inTransition[oldAdmin] != _msgSender()) {
            revert(Errors.INVALID_TRANSITION);
        }
        _inTransition[oldAdmin] = address(0);
        _grantRole(ADMIN_ROLE, _msgSender());
        _revokeRole(ADMIN_ROLE, oldAdmin);
        emit UpdateAdmin(oldAdmin);
    }

    /**
     * @dev former Admin can cancel its transition
     * @notice - Only Admin can call this function.
     */
    function cancelTransferAdmin()
        external
        onlyRole(ADMIN_ROLE)
        inTransition(_msgSender())
    {
        address adminToBeCanceled = _inTransition[_msgSender()];
        _inTransition[_msgSender()] = address(0);
        _revokeRole(ADMIN_ROLE, adminToBeCanceled);
        emit CancelTransferAdmin(adminToBeCanceled);
    }

    /**
     * @dev grant SETTER_ROLE to addresses
     * @param newSetters address[] - list of addresses going to get SETTER_ROLE
     * @notice - Only admin of SETTER_ROLE can call this function.
     */
    function batchGrantSetter(address[] memory newSetters)
        external
        onlyRole(getRoleAdmin(SETTER_ROLE))
    {
        _batchGrantSetter(newSetters);
    }

    /**
     * @dev grant SETTER_ROLE to addresses
     */
    function _batchGrantSetter(address[] memory newSetters) internal {
        for (uint256 i = 0; i < newSetters.length; i++) {
            if (newSetters[i] == address(0)) {
                revert(Errors.ZERO_ADDRESS);
            }
            _grantRole(SETTER_ROLE, newSetters[i]);
        }
    }

    /**
     * @dev grant NO_LIMIT_TRANSFER_ROLE to addresses
     * @param newNoLimitTransfers address[] - list of addresses going to get NO_LIMIT_TRANSFER_ROLE
     * @notice - Only admin of NO_LIMIT_TRANSFER_ROLE can call this function.
     */
    function batchGrantNoLimitTransfer(address[] memory newNoLimitTransfers)
        external
        onlyRole(getRoleAdmin(NO_LIMIT_TRANSFER_ROLE))
    {
        _batchGrantNoLimitTransfer(newNoLimitTransfers);
    }

    /**
     * @dev grant NO_LIMIT_TRANSFER_ROLE to addresses
     */
    function _batchGrantNoLimitTransfer(address[] memory newNoLimitTransfers)
        internal
    {
        for (uint256 i = 0; i < newNoLimitTransfers.length; i++) {
            if (newNoLimitTransfers[i] == address(0)) {
                revert(Errors.ZERO_ADDRESS);
            }
            _grantRole(NO_LIMIT_TRANSFER_ROLE, newNoLimitTransfers[i]);
        }
    }

    /**
     * @dev grant SMALL_AMOUNT_TRANSFER_ROLE to addresses
     * @param newSmallAmountTransfer address[] - list of addresses going to get SMALL_AMOUNT_TRANSFER_ROLE
     * @notice - Only admin of SMALL_AMOUNT_TRANSFER_ROLE can call this function.
     */
    function batchGrantSmallAmountTransfer(
        address[] memory newSmallAmountTransfer
    ) external onlyRole(getRoleAdmin(SMALL_AMOUNT_TRANSFER_ROLE)) {
        _batchGrantSmallAmountTransfer(newSmallAmountTransfer);
    }

    /**
     * @dev grant SMALL_AMOUNT_TRANSFER_ROLE to addresses
     */
    function _batchGrantSmallAmountTransfer(
        address[] memory newSmallAmountTransfer
    ) internal {
        for (uint256 i = 0; i < newSmallAmountTransfer.length; i++) {
            if (newSmallAmountTransfer[i] == address(0)) {
                revert(Errors.ZERO_ADDRESS);
            }
            _grantRole(SMALL_AMOUNT_TRANSFER_ROLE, newSmallAmountTransfer[i]);
        }
    }
}
