// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";


contract ChainManager is AccessControlUpgradeable, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    EnumerableSet.Bytes32Set internal dstChains;
    bytes32 public MAIN_CHAIN;

    event DstChainAdded(bytes32 indexed dstChain);
    event DstChainRemoved(bytes32 indexed dstChain);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    function initialize(bytes32 _mainChain) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        MAIN_CHAIN = _mainChain;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function addDstChains(bytes32[] memory _dstChains) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint i = 0; i < _dstChains.length; i++) {
            bytes32 chainCode = _dstChains[i];
            require(chainCode != MAIN_CHAIN, "Invalid dst chain");
            if (dstChains.add(chainCode)) {
                emit DstChainAdded(chainCode);
            }
        }
    }

    function removeDstChains(bytes32[] memory _dstChains) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint i = 0; i < _dstChains.length; i++) {
            bytes32 chainCode = _dstChains[i];
            if (dstChains.remove(chainCode)) {
                emit DstChainRemoved(chainCode);
            }
        }
    }

    function contains(bytes32 _dstChain) external view returns (bool) {
        return dstChains.contains(_dstChain);
    }

    function getAllDstChains() external view returns (bytes32[] memory) {
        return dstChains.values();
    }
}
