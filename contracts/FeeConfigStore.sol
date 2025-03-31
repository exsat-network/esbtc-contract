// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract FeeConfigStore is AccessControlUpgradeable, UUPSUpgradeable {
    struct FeeConfig {
        uint256 mintFee;
        uint256 burnFee;
        uint256 crosschainFee;
    }

    FeeConfig private _feeConfig;
    address public feeRecipient;

    event FeeConfigSet(uint256 mintFee, uint256 burnFee, uint256 crosschainFee);
    event FeeRecipientSet(address feeRecipient);

    function initialize(
        uint256 mintFee,
        uint256 burnFee,
        uint256 crosschainFee,
        address _feeRecipient
    ) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        setFeeConfig(mintFee, burnFee, crosschainFee);
        setFeeRecipient(_feeRecipient);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function setFeeConfig(
        uint256 mintFee,
        uint256 burnFee,
        uint256 crosschainFee
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(mintFee < 0.01 * 1e18, "Invalid mint fee");
        require(burnFee < 0.01 * 1e18, "Invalid burn fee");
        require(crosschainFee < 0.01 * 1e18, "Invalid crosschain fee");
        _feeConfig = FeeConfig(mintFee, burnFee, crosschainFee);
        emit FeeConfigSet(mintFee, burnFee, crosschainFee);
    }

    function setFeeRecipient(address _feeRecipient) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_feeRecipient != address(0), "Invalid fee recipient");
        feeRecipient = _feeRecipient;
        emit FeeRecipientSet(_feeRecipient);
    }

    function getFeeConfig() external view returns (FeeConfig memory) {
        return _feeConfig;
    }
}
