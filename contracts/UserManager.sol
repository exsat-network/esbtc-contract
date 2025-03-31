// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";


contract UserManager is AccessControlUpgradeable, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct UserInfo {
        bool locked;
        string depositAddress;
        string withdrawalAddress;
    }

    EnumerableSet.AddressSet internal qualifiedUsers;
    mapping(address => UserInfo) public userInfo;
    mapping(string => address) public depositAddressToUser;

    event QualifiedUserAdded(address indexed user, string depositAddress, string withdrawalAddress);
    event QualifiedUserEdited(address indexed user, string depositAddress, string withdrawalAddress);
    event QualifiedUserRemoved(address indexed user);
    event QualifiedUserLocked(address indexed user);
    event QualifiedUserUnlocked(address indexed user);

    function initialize() public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function addQualifiedUser(
        address user,
        string calldata depositAddress,
        string calldata withdrawalAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(qualifiedUsers.add(user), "User already qualified");
        require(depositAddressToUser[depositAddress] == address(0), "Deposit address used");
        userInfo[user] = UserInfo(false, depositAddress, withdrawalAddress);
        depositAddressToUser[depositAddress] = user;
        emit QualifiedUserAdded(user, depositAddress, withdrawalAddress);
    }

    function editQualifiedUser(
        address user,
        string calldata depositAddress,
        string calldata withdrawalAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(qualifiedUsers.contains(user), "User not qualified");
        require(!userInfo[user].locked, "User locked");
        string memory oldDeposit = userInfo[user].depositAddress;
        if (keccak256(bytes(depositAddress)) != keccak256(bytes(oldDeposit))) {
            require(depositAddressToUser[depositAddress] == address(0), "Deposit address used");
            delete depositAddressToUser[oldDeposit];
            userInfo[user].depositAddress = depositAddress;
            depositAddressToUser[depositAddress] = user;
        }
        userInfo[user].withdrawalAddress = withdrawalAddress;
        emit QualifiedUserEdited(user, depositAddress, withdrawalAddress);
    }

    function removeQualifiedUser(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(qualifiedUsers.remove(user), "User not qualified");
        string memory depAddr = userInfo[user].depositAddress;
        delete depositAddressToUser[depAddr];
        delete userInfo[user];
        emit QualifiedUserRemoved(user);
    }

    function lockQualifiedUser(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(qualifiedUsers.contains(user), "User not qualified");
        require(!userInfo[user].locked, "User already locked");
        userInfo[user].locked = true;
        emit QualifiedUserLocked(user);
    }

    function unlockQualifiedUser(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(qualifiedUsers.contains(user), "User not qualified");
        require(userInfo[user].locked, "User not locked");
        userInfo[user].locked = false;
        emit QualifiedUserUnlocked(user);
    }

    function isQualifiedUser(address user) external view returns (bool) {
        return qualifiedUsers.contains(user);
    }

    function getQualifiedUsers() external view returns (address[] memory) {
        return qualifiedUsers.values();
    }
}
