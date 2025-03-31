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

    function payFee(address from, address to, uint256 amount) external;
}

contract iBTCwBridge is AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    bytes32 public MAIN_CHAIN;
    address public minter;
    address public ibtcw;

    FeeConfigStore public feeStore;
    UserManager public userManager;
    RequestManager public requestManager;
    ChainManager public chainManager;

    // 用于记录跨链请求的确认情况
    mapping(bytes32 => bytes32) public crosschainRequestConfirmation;

    event TokenSet(address indexed _token);
    event MinterSet(address indexed _minter);
    event FeeStoreSet(address feeStore);
    event UserManagerSet(address userManager);
    event RequestManagerSet(address requestManager);
    event ChainManagerSet(address chainManager);

    function initialize(bytes32 _mainChain) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        MAIN_CHAIN = _mainChain;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    modifier onlyMinter() {
        require(msg.sender == minter, "Caller not minter");
        _;
    }

    function setToken(address _token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ibtcw = _token;
        emit TokenSet(_token);
    }

    function setMinter(address _minter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minter = _minter;
        emit MinterSet(_minter);
    }

    function setFeeStore(address _feeStore) external onlyRole(DEFAULT_ADMIN_ROLE) {
        feeStore = FeeConfigStore(_feeStore);
        emit FeeStoreSet(_feeStore);
    }

    function setUserManager(address _userManager) external onlyRole(DEFAULT_ADMIN_ROLE) {
        userManager = UserManager(_userManager);
        emit UserManagerSet(_userManager);
    }

    function setRequestManager(address _requestManager) external onlyRole(DEFAULT_ADMIN_ROLE) {
        requestManager = RequestManager(_requestManager);
        emit RequestManagerSet(_requestManager);
    }

    function setChainManager(address _chainManager) external onlyRole(DEFAULT_ADMIN_ROLE) {
        chainManager = ChainManager(_chainManager);
        emit ChainManagerSet(_chainManager);
    }

    function getSelfChainCode() public view returns (bytes32) {
        return bytes32(block.chainid);
    }

    function getRequestHash(RequestManager.Request memory r) internal pure returns (bytes32) {
        return keccak256(
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
    }

    function getCrossSourceRequestHash(RequestManager.Request memory src) internal pure returns (bytes32) {
        bytes memory extra = src.extra;
        RequestManager.Operation originalOp = src.op;
        src.op = RequestManager.Operation.CrosschainRequest;
        src.extra = "";
        bytes32 hashVal = getRequestHash(src);
        src.op = originalOp;
        src.extra = extra;
        return hashVal;
    }

    function addMintRequest(
        uint256 _amount,
        bytes32 _depositTxid,
        uint256 _outputIndex
    ) external whenNotPaused nonReentrant returns (bytes32) {
        require(_amount > 0, "Invalid amount");
        (bool locked, string memory depositAddr,) = userManager.userInfo(msg.sender);
        require(bytes(depositAddr).length > 0, "User not qualified");
        require(!locked, "User locked");

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

        FeeConfigStore.FeeConfig memory fc = feeStore.getFeeConfig();
        uint256 fee = fc.mintFee;
        r.fee = fee;
        r.amount = r.amount - fee;

        bytes32 hash = requestManager.addRequest(r);
        return hash;
    }

    function addBurnRequest(uint256 _amount) external whenNotPaused nonReentrant returns (bytes32) {
        require(_amount > 0, "Invalid amount");
        (bool locked, , string memory withdrawalAddr) = userManager.userInfo(msg.sender);
        require(bytes(withdrawalAddr).length > 0, "User not qualified");
        require(!locked, "User locked");

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

        FeeConfigStore.FeeConfig memory fc = feeStore.getFeeConfig();
        uint256 fee = fc.burnFee;
        r.fee = fee;
        r.amount = r.amount - fee;

        bytes32 hash = requestManager.addRequest(r);
        _payFee(fee, false);
        IiBTCwToken(ibtcw).burn(msg.sender, r.amount);
        return hash;
    }

    function addCrosschainRequest(
        bytes32 _targetChain,
        bytes memory _targetAddress,
        uint256 _amount
    ) public whenNotPaused nonReentrant returns (bytes32) {
        require(_amount > 0, "Invalid amount");
        require(chainManager.contains(_targetChain), "Target chain not allowed");

        (bool locked, string memory depositAddr,) = userManager.userInfo(msg.sender);
        require(bytes(depositAddr).length > 0, "User not qualified");
        require(!locked, "User locked");

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

        FeeConfigStore.FeeConfig memory fc = feeStore.getFeeConfig();
        uint256 fee = fc.crosschainFee;
        r.fee = fee;
        r.amount = r.amount - fee;

        bytes32 hash = requestManager.addRequest(r);
        _payFee(fee, false);
        IiBTCwToken(ibtcw).burn(msg.sender, r.amount);
        return hash;
    }

    function addEVMCrosschainRequest(
        uint256 _targetChainId,
        address _targetAddress,
        uint256 _amount
    ) external returns (bytes32) {
        return addCrosschainRequest(
            bytes32(_targetChainId),
            abi.encode(_targetAddress),
            _amount
        );
    }

    function confirmCrosschainRequest(RequestManager.Request memory r) external onlyMinter whenNotPaused nonReentrant {
        require(r.amount > 0, "Invalid request amount");
        require(r.dstChain == getSelfChainCode(), "Dst chain not match");
        require(r.op == RequestManager.Operation.CrosschainConfirm, "Not CrosschainConfirm request");
        require(r.status == RequestManager.Status.Unused, "Status should not be used");
        require(r.extra.length == 32, "Invalid extra: not valid bytes32");
        require(r.dstAddress.length == 32, "Invalid dstAddress length");
        require(abi.decode(r.dstAddress, (uint256)) <= type(uint160).max, "Invalid dstAddress: not address");

        bytes32 srcHash = abi.decode(r.extra, (bytes32));
        require(getCrossSourceRequestHash(r) == srcHash, "Source request hash is incorrect");
        require(crosschainRequestConfirmation[srcHash] == bytes32(0), "Source request already confirmed");

        r.nonce = requestManager.nonce();
        bytes32 dstHash = requestManager.addRequest(r);
        crosschainRequestConfirmation[srcHash] = dstHash;

        IiBTCwToken(ibtcw).mint(abi.decode(r.dstAddress, (address)), r.amount);
    }

    function confirmMintRequest(uint256 index) external onlyMinter whenNotPaused nonReentrant {
        require(index < requestManager.nonce(), "Invalid request index");

        RequestManager.Request memory r = requestManager.getRequest(index);

        require(r.amount > 0, "Invalid request amount");
        require(r.op == RequestManager.Operation.Mint, "Not a Mint request");
        require(r.dstChain == getSelfChainCode(), "Dst chain mismatch");
        require(r.status == RequestManager.Status.Pending, "Request must be pending");
        require(r.dstAddress.length == 32, "Invalid dstAddress length");
        require(abi.decode(r.dstAddress, (uint256)) <= type(uint160).max, "Invalid dstAddress: not address");

        requestManager.confirmRequest(index);

        address user = abi.decode(r.dstAddress, (address));
        IiBTCwToken(ibtcw).mint(user, r.amount);
    }


    function _payFee(uint256 _fee, bool viaMint) internal {
        if (_fee == 0) return;
        address feeRecipient = feeStore.feeRecipient();
        if (viaMint) {
            IiBTCwToken(ibtcw).mint(feeRecipient, _fee);
        } else {
            IiBTCwToken(ibtcw).payFee(msg.sender, feeRecipient, _fee);
        }
    }
}
