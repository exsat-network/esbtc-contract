// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract RequestManager is AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using RequestLib for Request;

    enum Operation { Nop, Mint, Burn, CrosschainRequest, CrosschainConfirm }
    enum Status { Unused, Pending, Confirmed }

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

    bytes32[] public requestHashes;
    mapping(bytes32 => Request) public requests;

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
        require(requestHashes.length < type(uint128).max, "Nonce overflow");
        return uint128(requestHashes.length);
    }

    function getRequest(uint256 index) external view returns (Request memory) {
        require(index < requestHashes.length, "Invalid index");
        bytes32 hash = requestHashes[index];
        return requests[hash];
    }

    function getRequestByHash(bytes32 _hash) external view returns (Request memory) {
        return requests[_hash];
    }

    function addRequest(Request memory r) external returns (bytes32) {
        require(msg.sender == bridge, "Only bridge can call addRequest");
        require(r.nonce == nonce(), "Nonce mismatch");
        bytes32 hash = r.getRequestHash();
        requests[hash] = r;
        requestHashes.push(hash);
        emit RequestAdded(hash, r.op, r);
        return hash;
    }

    /// @notice Confirm the request and update its extra field with new data.
    /// @param _hash The unique identifier of the request.
    /// @param newExtra The new extra data to store.
    function confirmRequestWithExtra(bytes32 _hash, bytes memory newExtra) external {
        require(msg.sender == bridge, "Only bridge can call confirmRequest");
        Request storage r = requests[_hash];
        require(r.status == Status.Pending, "Request not pending");
        r.extra = newExtra;
        r.status = Status.Confirmed;
        emit RequestConfirmed(_hash);
    }

    /// @notice Confirm the request without updating extra data.
    function confirmRequest(bytes32 _hash) external {
        require(msg.sender == bridge, "Only bridge can call confirmRequest");
        Request storage r = requests[_hash];
        require(r.status == Status.Pending, "Request not pending");
        r.status = Status.Confirmed;
        emit RequestConfirmed(_hash);
    }
}

library RequestLib {
    function getRequestHash(
        RequestManager.Request memory self
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                self.op,
                self.nonce,
                self.srcChain,
                self.srcAddress,
                self.dstChain,
                self.dstAddress,
                self.amount,
                self.fee,
                self.extra
            )
        );
    }

    function getCrossSourceRequestHash(
        RequestManager.Request memory self
    ) internal pure returns (bytes32 _hash) {
        bytes memory extra = self.extra;
        self.op = RequestManager.Operation.CrosschainRequest;
        self.extra = "";
        _hash = getRequestHash(self);
        self.op = RequestManager.Operation.CrosschainConfirm;
        self.extra = extra;
    }
}