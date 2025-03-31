// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";


contract RequestManager is AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    enum Operation {Nop, Mint, Burn, CrosschainRequest, CrosschainConfirm}
    enum Status {Unused, Pending, Confirmed, Rejected}

    struct Request {
        Operation op;
        Status status;
        uint128 nonce;
        bytes32 srcChain;
        bytes srcAddress;
        bytes32 dstChain;
        bytes dstAddress;
        uint256 amount;
        uint256 fee;
        bytes extra;
    }

    Request[] public requests;
    address public bridge;

    event RequestAdded(bytes32 indexed hash, Operation op, Request requestData);
    event RequestConfirmed(bytes32 indexed hash);
    event BridgeSet(address indexed bridgeAddress);

    function initialize() public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function setBridge(address _bridge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_bridge != address(0), "Invalid bridge address");
        bridge = _bridge;
        emit BridgeSet(_bridge);
    }

    function nonce() public view returns (uint128) {
        require(requests.length < type(uint128).max, "Nonce overflow");
        return uint128(requests.length);
    }

    function getRequest(uint256 index) external view returns (Request memory) {
        require(index < requests.length, "Invalid index");
        return requests[index];
    }

    function addRequest(Request memory r) external returns (bytes32) {
        require(msg.sender == bridge, "Only bridge can call addRequest");
        require(r.nonce == nonce(), "Nonce mismatch");
        bytes32 hash = keccak256(
            abi.encode(
                r.op,
                r.nonce,
                r.srcChain,
                r.srcAddress,
                r.dstChain,
                r.dstAddress,
                r.amount,
                r.fee,
                r.extra
            )
        );
        requests.push(r);
        emit RequestAdded(hash, r.op, r);
        return hash;
    }

    function confirmRequest(uint256 index) external {
        require(msg.sender == bridge, "Only bridge can call confirmRequest");
        require(index < requests.length, "Invalid index");
        Request storage r = requests[index];
        require(r.status == Status.Pending, "Request not pending");
        r.status = Status.Confirmed;
        bytes32 hash = keccak256(
            abi.encode(
                r.op,
                r.nonce,
                r.srcChain,
                r.srcAddress,
                r.dstChain,
                r.dstAddress,
                r.amount,
                r.fee,
                r.extra
            )
        );
        emit RequestConfirmed(hash);
    }
}
