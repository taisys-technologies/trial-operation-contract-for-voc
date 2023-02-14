// SPDX-License-Identifier: MIT

pragma solidity 0.8.12;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Errors} from "./libraries/Errors.sol";

contract AccessControlUpgradeableCustom is
    Initializable,
    AccessControlUpgradeable
{
    /**
     * Global Variables
     */
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    mapping(address => address) private _inTransition;

    /**
     * Events
     */

    event TransferAdmin(address adminAddress);
    event UpdateAdmin(address oldAdminAddress);
    event CancelTransferAdmin(address newAdminAddress);

    /**
     * modifier
     */

    /**
     * @dev Modifier to make a function callable only when the transition exist.
     *
     * Requirements:
     *
     * - The transition must exist.
     */
    modifier inTransition(address oldAdmin) {
        require(
            _inTransition[oldAdmin] != address(0),
            Errors.NOT_IN_TRANSITION
        );
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
        require(
            _inTransition[_msgSender()] == address(0),
            Errors.ALREADY_IN_TRANSITION
        );
        _;
    }

    /**
     * Functions
     */

    function __AccessControlCustom_init(
        address newAdmin,
        address[] memory newSetters
    ) internal onlyInitializing {
        require(newAdmin != address(0), Errors.ZERO_ADDRESS);

        __AccessControl_init();

        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _setRoleAdmin(SETTER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(UPGRADER_ROLE, ADMIN_ROLE);

        _grantRole(ADMIN_ROLE, newAdmin);
        _batchGrantSetter(newSetters);
    }

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
     * @notice - Only admin can call this function.
     */
    function transferAdmin(address newAdmin)
        external
        onlyRole(ADMIN_ROLE)
        notInTransition
    {
        require(
            newAdmin != address(0) && !hasRole(ADMIN_ROLE, newAdmin),
            Errors.GRANT_ROLE_INVALID_ADDRESS
        );

        _inTransition[_msgSender()] = newAdmin;
        emit TransferAdmin(newAdmin);
    }

    /**
     * @dev the address who gets admin from transition are able to accept and revoke the old Admin
     * @param oldAdmin address - the original Admin address
     */
    function updateAdmin(address oldAdmin) external inTransition(oldAdmin) {
        require(
            _inTransition[oldAdmin] == _msgSender(),
            Errors.INVALID_TRANSITION
        );

        _inTransition[oldAdmin] = address(0);
        _grantRole(ADMIN_ROLE, _msgSender());
        _revokeRole(ADMIN_ROLE, oldAdmin);
        emit UpdateAdmin(oldAdmin);
    }

    /**
     * @dev former Admin can cancel its transition
     * @notice - Only admin can call this function.
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
     * @notice - Only admin can call this function.
     */
    function batchGrantSetter(address[] memory newSetters)
        external
        onlyRole(getRoleAdmin(SETTER_ROLE))
    {
        _batchGrantSetter(newSetters);
    }

    /**
     * @dev grant SETTER_ROLE to addresses
     * @param newSetters address[] - list of addresses going to get SETTER_ROLE
     */
    function _batchGrantSetter(address[] memory newSetters) internal {
        for (uint256 i = 0; i < newSetters.length; i++) {
            require(newSetters[i] != address(0), Errors.ZERO_ADDRESS);
            _grantRole(SETTER_ROLE, newSetters[i]);
        }
    }
}
