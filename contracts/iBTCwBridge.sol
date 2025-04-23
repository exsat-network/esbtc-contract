// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./FeeConfigStore.sol";
import "./UserManager.sol";
import "./RequestManager.sol";
import "./ChainManager.sol";

interface IiBTCwToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

contract iBTCwBridge is AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using RequestLib for RequestManager.Request;

    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");

    bytes32 public MAIN_CHAIN;
    address public minter;
    address public ibtcw;

    FeeConfigStore public feeStore;
    UserManager public userManager;
    RequestManager public requestManager;
    ChainManager public chainManager;

    // Mapping for cross-chain confirmations: source request hash => destination chain request hash
    mapping(bytes32 => bytes32) public crosschainRequestConfirmation;
    // Prevent reusing the same BTC deposit tx (using a unique key from deposit txid and output index)
    mapping(bytes32 => bytes32) public usedDepositTxs;
    // Prevent reusing the same BTC withdrawal tx (using a unique key from withdrawal txid and output index)
    mapping(bytes32 => bytes32) public usedWithdrawalTxs;

    event MinterSet(address indexed _minter);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    function initialize(
        bytes32 _mainChain,
        address _token,
        address _minter,
        address _feeStore,
        address _userManager,
        address _requestManager,
        address _chainManager
    ) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        MAIN_CHAIN = _mainChain;

        // Validate non-zero addresses
        require(_token          != address(0), "Bridge: token is zero address");
        require(_minter         != address(0), "Bridge: minter is zero address");
        require(_feeStore       != address(0), "Bridge: feeStore is zero address");
        require(_userManager    != address(0), "Bridge: userManager is zero address");
        require(_requestManager != address(0), "Bridge: requestManager is zero address");
        require(_chainManager   != address(0), "Bridge: chainManager is zero address");

        // Set token and managers
        ibtcw = _token;
        minter = _minter;
        feeStore = FeeConfigStore(_feeStore);
        userManager = UserManager(_userManager);
        requestManager = RequestManager(_requestManager);
        chainManager = ChainManager(_chainManager);

        emit MinterSet(_minter);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    modifier onlyMinter() {
        require(msg.sender == minter, "Caller not minter");
        _;
    }

    function setMinter(address _minter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_minter != address(0), "Bridge: minter is zero address");
        minter = _minter;
        emit MinterSet(_minter);
    }

    function getSelfChainCode() public view returns (bytes32) {
        return bytes32(block.chainid);
    }

    /// @notice Submit a mint request. The deposit txid and output index are recorded to prevent reusing the same BTC deposit.
    function addMintRequest(
        uint256 _amount,
        bytes32 _depositTxid,
        uint256 _outputIndex
    ) external payable whenNotPaused nonReentrant returns (bytes32) {
        require(_amount > 0, "Invalid amount");
        (bool locked, string memory depositAddr, ) = userManager.userInfo(msg.sender);
        require(bytes(depositAddr).length > 0, "User not qualified");
        require(!locked, "User locked");

        FeeConfigStore.FeeConfig memory fc = feeStore.getFeeConfig();
        uint256 fee = fc.mintFee;
        require(msg.value == fee, "Incorrect fee sent");

        // Create a unique key for the deposit and ensure it hasn't been used
        bytes32 depositKey = keccak256(abi.encode(_depositTxid, _outputIndex));
        require(usedDepositTxs[depositKey] == bytes32(0), "Deposit tx already used");
        usedDepositTxs[depositKey] = depositKey;

        RequestManager.Request memory r;
        r.nonce = requestManager.nonce();
        r.op = RequestManager.Operation.Mint;
        r.status = RequestManager.Status.Pending;
        r.srcChain = MAIN_CHAIN;
        r.srcAddress = bytes(depositAddr);
        r.dstChain = getSelfChainCode();
        r.dstAddress = abi.encode(msg.sender);
        r.amount = _amount;
        r.extra = abi.encode(_depositTxid, _outputIndex);
        r.fee = fee;

        bytes32 hash = requestManager.addRequest(r);
        _payFee(fee);
        return hash;
    }

    /// @notice Submit a burn request.
    function addBurnRequest(uint256 _amount) external payable whenNotPaused nonReentrant returns (bytes32) {
        require(_amount > 0, "Invalid amount");
        (bool locked, , string memory withdrawalAddr) = userManager.userInfo(msg.sender);
        require(bytes(withdrawalAddr).length > 0, "User not qualified");
        require(!locked, "User locked");

        FeeConfigStore.FeeConfig memory fc = feeStore.getFeeConfig();
        uint256 fee = fc.burnFee;
        require(msg.value == fee, "Incorrect fee sent");

        RequestManager.Request memory r;
        r.nonce = requestManager.nonce();
        r.op = RequestManager.Operation.Burn;
        r.status = RequestManager.Status.Pending;
        r.srcChain = getSelfChainCode();
        r.srcAddress = abi.encode(msg.sender);
        r.dstChain = MAIN_CHAIN;
        r.dstAddress = bytes(withdrawalAddr);
        r.amount = _amount;
        r.extra = "";
        r.fee = fee;

        bytes32 hash = requestManager.addRequest(r);
        _payFee(fee);
        IiBTCwToken(ibtcw).burn(msg.sender, r.amount);
        return hash;
    }

    /// @notice Submit a cross-chain request.
    function addCrosschainRequest(
        bytes32 _targetChain,
        bytes memory _targetAddress,
        uint256 _amount
    ) public payable whenNotPaused nonReentrant returns (bytes32) {
        require(_amount > 0, "Invalid amount");
        require(chainManager.contains(_targetChain), "Target chain not allowed");

        (bool locked, string memory depositAddr, ) = userManager.userInfo(msg.sender);
        require(bytes(depositAddr).length > 0, "User not qualified");
        require(!locked, "User locked");

        FeeConfigStore.FeeConfig memory fc = feeStore.getFeeConfig();
        uint256 fee = fc.crosschainFee;
        require(msg.value == fee, "Incorrect fee sent");

        RequestManager.Request memory r;
        r.nonce = requestManager.nonce();
        r.op = RequestManager.Operation.CrosschainRequest;
        r.status = RequestManager.Status.Pending;
        r.srcChain = getSelfChainCode();
        r.srcAddress = abi.encode(msg.sender);
        r.dstChain = _targetChain;
        r.dstAddress = _targetAddress;
        r.amount = _amount;
        r.extra = "";
        r.fee = fee;

        bytes32 hash = requestManager.addRequest(r);
        _payFee(fee);
        // For cross-chain requests, tokens are burned first and minted on the destination chain upon confirmation.
        IiBTCwToken(ibtcw).burn(msg.sender, r.amount);
        return hash;
    }

    function addEVMCrosschainRequest(
        uint256 _targetChainId,
        address _targetAddress,
        uint256 _amount
    ) external payable returns (bytes32) {
        return addCrosschainRequest(
            bytes32(_targetChainId),
            abi.encode(_targetAddress),
            _amount
        );
    }

    /// @notice Called by the minter to confirm a cross-chain request.
    function confirmCrosschainRequest(RequestManager.Request memory r) external onlyMinter whenNotPaused nonReentrant {
        require(r.amount > 0, "Invalid request amount");
        require(r.dstChain == getSelfChainCode(), "Dst chain not match");
        require(r.op == RequestManager.Operation.CrosschainConfirm, "Not CrosschainConfirm request");
        require(r.status == RequestManager.Status.Unused, "Status should not be used");
        require(r.extra.length == 32, "Invalid extra: not valid bytes32");
        require(r.dstAddress.length == 32, "Invalid dstAddress length");
        require(abi.decode(r.dstAddress, (uint256)) <= type(uint160).max, "Invalid dstAddress: not address");

        // Get source request hash from r.extra
        bytes32 srcHash = abi.decode(r.extra, (bytes32));
        require(r.getCrossSourceRequestHash() == srcHash, "Source request hash is incorrect");
        require(crosschainRequestConfirmation[srcHash] == bytes32(0), "Source request already confirmed");

        // Override src nonce to dst nonce.
        r.nonce = requestManager.nonce();
        // Add the cross-chain confirmation request in RequestManager
        bytes32 dstHash = requestManager.addRequest(r);
        crosschainRequestConfirmation[srcHash] = dstHash;

        address dst = abi.decode(r.dstAddress, (address));
        (bool locked, , ) = userManager.userInfo(dst);
        require(!locked, "UserManager: user locked");

        IiBTCwToken(ibtcw).mint(dst, r.amount);
    }

    /// @notice Called by the minter to confirm a mint request.
    function confirmMintRequest(bytes32 _hash) external onlyMinter whenNotPaused nonReentrant {
        RequestManager.Request memory r = requestManager.getRequestByHash(_hash);
        require(r.amount > 0, "Invalid request amount");
        require(r.op == RequestManager.Operation.Mint, "Not a Mint request");
        require(r.dstChain == getSelfChainCode(), "Dst chain mismatch");
        require(r.status == RequestManager.Status.Pending, "Request must be pending");
        require(r.dstAddress.length == 32, "Invalid dstAddress length");
        require(abi.decode(r.dstAddress, (uint256)) <= type(uint160).max, "Invalid dstAddress: not address");

        requestManager.confirmRequest(_hash);

        address user = abi.decode(r.dstAddress, (address));
        (bool locked, , ) = userManager.userInfo(user);
        require(!locked, "UserManager: user locked");

        IiBTCwToken(ibtcw).mint(user, r.amount);
    }

    /// @notice Called by the minter to confirm a burn request, providing BTC withdrawal info.
    function confirmBurnRequest(
        bytes32 _hash,
        bytes32 _withdrawalTxid,
        uint256 _outputIndex
    ) external onlyMinter whenNotPaused nonReentrant {
        require(uint256(_withdrawalTxid) != 0, "Empty withdraw txid");

        RequestManager.Request memory r = requestManager.getRequestByHash(_hash);
        require(r.op == RequestManager.Operation.Burn, "Not Burn request");
        require(r.amount > 0, "Invalid request amount");
        require(r.status == RequestManager.Status.Pending, "Request not pending");

        bytes memory _withdrawalTxData = abi.encode(_withdrawalTxid, _outputIndex);
        bytes32 _withdrawalDataHash = keccak256(_withdrawalTxData);
        require(usedWithdrawalTxs[_withdrawalDataHash] == bytes32(0), "Used BTC withdrawal tx");
        usedWithdrawalTxs[_withdrawalDataHash] = _hash;

        // Call confirmRequestWithExtra to update the extra field with the BTC withdrawal data and confirm the request.
        requestManager.confirmRequestWithExtra(_hash, _withdrawalTxData);
    }

    /// @notice Pause all bridge operations
    function pause() external onlyRole(PAUSE_ROLE) {
        _pause();
    }

    /// @notice Unpause bridge operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _payFee(uint256 _fee) internal {
        if (_fee == 0) return;
        address feeRecipient = feeStore.feeRecipient();
        (bool success, ) = feeRecipient.call{value: _fee}("");
        require(success, "Fee transfer failed");
    }

    receive() external payable {}
}
