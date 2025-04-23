// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract iBTCwToken is ERC20Upgradeable, AccessControlUpgradeable, PausableUpgradeable, UUPSUpgradeable {
    // Roles
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Events for blacklist management
    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);

    // Blacklist mapping
    mapping(address => bool) private _blacklist;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    function initialize(
        string memory name_,
        string memory symbol_
    ) public initializer {
        __ERC20_init(name_, symbol_);
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _checkPausedAndBlacklist(to);  // Check blacklist and paused status
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyRole(MINTER_ROLE) {
        _checkPausedAndBlacklist(from);  // Check blacklist and paused status
        _burn(from, amount);
    }

    // Blacklist management
    function addToBlacklist(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _blacklist[account] = true;
        emit Blacklisted(account);
    }

    function removeFromBlacklist(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _blacklist[account] = false;
        emit UnBlacklisted(account);
    }

    function isBlacklisted(address account) public view returns (bool) {
        return _blacklist[account];
    }

    // Pause/Unpause functions
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // Internal function to check paused state and blacklist status
    function _checkPausedAndBlacklist(address account) internal view whenNotPaused {
        require(!_blacklist[account], "iBTCwToken: account is blacklisted");
    }

    // Override ERC20 _transfer to include pause and blacklist checks
    function _transfer(address sender, address recipient, uint256 amount) internal override {
        _checkPausedAndBlacklist(sender);
        _checkPausedAndBlacklist(recipient);
        super._transfer(sender, recipient, amount);
    }
}
