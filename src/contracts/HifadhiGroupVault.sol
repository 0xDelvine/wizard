// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
// Local imports
import "../contracts/HifadhiContributionCycleManager.sol";

/**
 * @title HifadhiGroupVault
 * @dev Vault contract for holding and distributing group funds
 */
contract HifadhiGroupVault is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant GROUP_ROLE = keccak256("GROUP_ROLE");

    address public immutable groupContract;

    HifadhiContributionCycleManager internal cycleManager;

    mapping(address => bool) public supportedAssets;
    address public initialAsset;

    // Distribution Round
    struct Distribution {
        uint256 id;
        address asset;
        uint256 totalAmount;
        mapping(address => uint256) memberShares;
        mapping(address => bool) claimed;
        bool isActive;
    }

    uint256 public currentDistributionId;
    mapping(uint256 => Distribution) public distributions;
    mapping(bytes32 cycleId => mapping(address _vaultAddress => uint256 _vaultBal)) public CycleAssetBalances;
    mapping(bytes32 cycleId => mapping(address => uint256)) public CycleUserBalances; // mapping of cycleId to user balances
    mapping(bytes32 cycleId => mapping(address => uint256)) public CycleUserShares; // mapping of cycleId to user shares
    mapping(bytes32 cycleId => mapping(address => uint256)) public CycleUserClaimableAmount; // mapping of cycleId to user claimable amount
    mapping(bytes32 cycleId => mapping(address => uint256)) public CycleUserClaimedAmount; // mapping of cycleId to user claimed amount

    event AssetAdded(address asset);
    event FundsReceived(address asset, uint256 amount);
    event DistributionCreated(uint256 distributionId, address asset, uint256 totalAmount);
    event FundsClaimed(uint256 distributionId, address member, uint256 amount);

    constructor(address _groupContract, address _initialAsset) {
        require(_groupContract != address(0), "InvalidGroupContract");
        

        groupContract = _groupContract;

        // Grant roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GROUP_ROLE, _groupContract);

        // Set role admin
        _setRoleAdmin(GROUP_ROLE, DEFAULT_ADMIN_ROLE);

        // Add initial asset if provided
        if (_initialAsset != address(0)) {
            supportedAssets[_initialAsset] = true;
            emit AssetAdded(_initialAsset);
        }
    }

    function setCycleManager(address _cycleManager) external {  //contract to manage cycles
        require(_cycleManager != address(0), "InvalidCycleManager");
        cycleManager = HifadhiContributionCycleManager(_cycleManager);
    }
    function getCycleManager() external view returns (address) {
        return address(cycleManager);
    }

    modifier onlyGroup() {
        require(hasRole(GROUP_ROLE, msg.sender), "Caller is not the group contract");
        _;
    }

    /**
     * @dev Add support for a new asset
     * @param asset Address of the asset to add
     */
    function addAsset(address asset) external onlyGroup {
        require(asset != address(0), "Invalidassetaddress");
        require(!supportedAssets[asset], "Assetalreadyadded");
        supportedAssets[asset] = true;
        emit AssetAdded(asset);
    }
    // payable function to receive funds to our vault, transfer to send to beefy, withdraw to claim dependent on ContributionCycleManager

    //TODO: Add onlyGroup modifier to this function for security, purged temporarily for testing 

    function depositToGroupVault(address asset, uint256 amount, bytes32 _cycleId, address _vaultAddress)
        external
        payable
    {
        require(supportedAssets[asset], "Unsupportedasset");
        require(amount > 0, "InvalidAmount");
        require(address(cycleManager) != address(0), "CycleManagerNotSet");
        //assumes this contract is the vault that the user wants to deposit to
        if (_vaultAddress == address(this)) {
            require(
                cycleManager._isCycleDurationExpired(_cycleId) == false, "CyclenotExp"
            ); // Preventing late deposits when the cycle has already expired / progressed past the contribution phase.
            // Transfer the asset to this contract
            IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
            CycleAssetBalances[_cycleId][address(this)] += amount;
            CycleUserBalances[_cycleId][msg.sender] += amount;
            emit FundsReceived(asset, amount);
        } else {
            require(
                cycleManager._isCycleDurationExpired(_cycleId) == false, "CyclenotExp"
            );
            // Transfer the asset to the vault address
            IERC20(asset).safeTransferFrom(msg.sender, _vaultAddress, amount);
            CycleAssetBalances[_cycleId][_vaultAddress] += amount;
            CycleUserBalances[_cycleId][msg.sender] += amount;
            emit FundsReceived(asset, amount);
        }
    }

    // Lets make this function more modular, composable, reusable
    function getVaultCycleBalance(address _asset, address _vaultAddress, bytes32 _cycleId)
        public
        view
        returns (uint256)
    {
        require(supportedAssets[_asset], "Unsupportedasset");
        // If the vault address if the current in context:
        if (_asset == initialAsset) {
            return _getCurrVaultBalInCycleX(_cycleId, _vaultAddress);
        }
        // If the vault address is not the current in context / the bal is for another vault\
        // Basically retrieves bal of vault address where asset != initialAsset
        return IERC20(_asset).balanceOf(_vaultAddress);
    }
    function getUserDepositForCycle(address _user, bytes32 _cycleId)
        public
        view
        returns (uint256)
    {
        return CycleUserBalances[_cycleId][_user];
    }


    // Only works :IF the asset in question is the initial asset.
    function _getCurrVaultBalInCycleX(bytes32 _cycleId, address _vaultAddress) internal view returns (uint256) {
        uint256 vaultBalance;
        if (_vaultAddress == address(this)) {
            vaultBalance = (CycleAssetBalances[_cycleId][address(this)]);
        } else {
            vaultBalance = (CycleAssetBalances[_cycleId][_vaultAddress]);
        }
        return vaultBalance > 0 ? vaultBalance : 0;
    }
    /**
     * @dev Receives funds from Beefy vault withdrawal
     * @param amount Amount of funds received
     */

    function receiveFunds(uint256 amount) external onlyGroup {
        require(amount > 0, "Amount must be greater than 0");

        // We don't check specific asset here as the group contract
        // is responsible for ensuring the correct asset is sent

        emit FundsReceived(msg.sender, amount);
    }

    /**
     * @dev Creates a new distribution for members to claim
     * @param members Array of member addresses
     * @param shares Array of member shares (must match members array length)
     */
    function createDistribution(address[] calldata members, uint256[] calldata shares)
        external
        onlyGroup
        nonReentrant
    {
        require(members.length == shares.length, "Arrays length mismatch");
        require(members.length > 0, "Empty members array");

        // Determine which asset was sent by checking balances
        address asset;
        uint256 highestBalance = 0;

        // Find the asset with the highest balance
        // This is a simplification - in production you might want to specify the asset
        for (uint256 i = 0; i < members.length; i++) {
            if (IERC20(asset).balanceOf(address(this)) > highestBalance) {  //@Craig - WOULD ONLY LOOP ONCE(that is, if asset was initialised)
                asset = msg.sender;  // @Craig msg.sender = HifadhiContrCycleManager; NOT ERC20 token.
                highestBalance = IERC20(asset).balanceOf(address(this));  
            }
        }

        require(highestBalance > 0, "No funds to distribute");
        require(supportedAssets[asset], "Unsupported asset");

        // Validate total shares match available balance
        uint256 totalShares = 0;
        for (uint256 i = 0; i < shares.length; i++) {
            totalShares += shares[i];
        }
        require(totalShares <= highestBalance, "Total shares exceed available balance");

        currentDistributionId++;
        Distribution storage dist = distributions[currentDistributionId];
        dist.id = currentDistributionId;
        dist.asset = asset;
        dist.totalAmount = highestBalance;
        dist.isActive = true;

        // Record member shares
        for (uint256 i = 0; i < members.length; i++) {
            require(members[i] != address(0), "Invalid member address");
            require(shares[i] > 0, "Invalid share amount");
            dist.memberShares[members[i]] = shares[i];
        }

        emit DistributionCreated(currentDistributionId, asset, highestBalance);
    }

    /**ress member) external onlyAdmin {
        require(hasRole(MEMBER_ROLE, member), "Not a member");

     * @dev Allows members to claim their share of the distribution
     */
    function claimDistribution(uint256 distributionId) external nonReentrant {
        Distribution storage dist = distributions[distributionId];
        require(dist.isActive, "Distribution not active");
        require(dist.memberShares[msg.sender] > 0, "No shares to claim");
        require(!dist.claimed[msg.sender], "Already claimed");

        uint256 shareAmount = dist.memberShares[msg.sender];
        dist.claimed[msg.sender] = true;

        IERC20(dist.asset).safeTransfer(msg.sender, shareAmount);

        emit FundsClaimed(distributionId, msg.sender, shareAmount);
    }

    /**
     * @dev View function to check member's claimable amount
     */
    function getClaimableAmount(uint256 distributionId, address member) external view returns (uint256) {
        Distribution storage dist = distributions[distributionId];
        if (!dist.isActive || dist.claimed[member]) {
            return 0;
        }
        return dist.memberShares[member];
    }

    /**
     * @dev Check if a member has claimed their share
     */
    function hasClaimed(uint256 distributionId, address member) external view returns (bool) {
        return distributions[distributionId].claimed[member];
    }

    /**
     * @dev Get all active distributions
     */
    function getAllDistributions() external view returns (uint256[] memory) {
        uint256[] memory activeDistributions = new uint256[](currentDistributionId);
        uint256 count = 0;

        for (uint256 i = 1; i <= currentDistributionId; i++) {
            if (distributions[i].isActive) {
                activeDistributions[count] = i;
                count++;
            }
        }

        // Create properly sized array
        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = activeDistributions[i];
        }

        return result;
    }

    /**
     * @dev Get distribution details
     */
    function getDistributionInfo(uint256 distributionId)
        external
        view
        returns (uint256 id, address asset, uint256 totalAmount, bool isActive)
    {
        Distribution storage dist = distributions[distributionId];
        return (dist.id, dist.asset, dist.totalAmount, dist.isActive);
    }

    /**
     * @dev Emergency function to handle any stuck tokens
     * Only callable by admin in case funds get stuck
     */
    function rescueTokens(address token, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(token).safeTransfer(msg.sender, amount);
    }

    function getVaultAddress() external view returns (address) {
        return address(this);
    }
}
