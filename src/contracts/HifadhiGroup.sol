// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "../interfaces/IBeefyWrapper.sol";
import "./HifadhiGroupVault.sol";               

/**
 * @title HifadhiGroup
 * @dev A contract for managing group-based vaults and member contributions using Beefy vaults.
 * Implements role-based access control, pausable operations, and reentrancy protection.
 * Allows members to deposit, request withdrawals, and manage vaults within the group.
 * Supports join requests and tracks member status and contributions.
 * Utilizes OpenZeppelin libraries for security and access control.
 */
contract HifadhiGroup is ReentrancyGuard, AccessControl, Pausable, Initializable {
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MEMBER_ROLE = keccak256("MEMBER_ROLE");

    // State variables
    string public name;
    uint256 public minContribution;
    uint256 public totalDeposited;
    uint256 public minSignatures;

    // Vault management
    struct VaultInfo {
        address vaultAddress;
        address asset;
        uint256 totalDeposited;
        uint256 totalShares;
        bool isActive;
    }

    mapping(address => VaultInfo) public vaults;
    address[] public activeVaults;

    HifadhiGroupVault public groupVault;

    // Member tracking
    address[] private groupMembers;
    uint256 private _withdrawalIds;

    struct WithdrawalRequest {
        address requester;
        uint256 amount;
        address vaultAddress;
        uint256 signaturesRequired;
        uint256 signaturesReceived;
        mapping(address => bool) hasApproved;
        bool executed;
        bool cancelled;
    }

    struct JoinRequestStatus {
        string PENDING;
        string APPROVED;
        string REJECTED;
    }

    JoinRequestStatus public joinStatus = JoinRequestStatus(
        "PENDING", // Index 0
        "APPROVED", // Index 1
        "REJECTED" // Index 2
    );

    struct JoinRequestDetails {
        address requester;
        uint256 groupId;
        uint256 currTStamp;
        string status; // Stores "PENDING"/"APPROVED"/"REJECTED"
        uint256 joinRequestId;
    }

    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;
    mapping(address => mapping(address => uint256)) public userVaultDeposits;
    mapping(address => mapping(address => uint256)) public userVaultShares;
    mapping(address => bool) public isActiveMember;

    mapping(uint256 _groupId => uint256 _nextAvailableId) private _nextRequestId;
    /**
     * O(1) 2d table for getting specific join requests
     * //Find all requests for a group
     * Find specific requests within a group
     * Keep requests organized by group
     * // Sample Mapping Access
     * // groupJoinRequests[1][1] -> First request for group 1
     * // groupJoinRequests[1][2] -> Second request for group 1
     * // groupJoinRequests[2][1] -> First request for group 2
     */
    mapping(uint256 => mapping(uint256 => JoinRequestDetails)) public groupJoinRequests;

    // Events
    event Deposited(address indexed user, address indexed vault, uint256 amount, uint256 shares);
    event WithdrawalRequested(
        uint256 indexed requestId, address indexed requester, address indexed vault, uint256 amount
    );
    event WithdrawalApproved(uint256 indexed requestId, address indexed approver);
    event WithdrawalExecuted(uint256 indexed requestId, address receiver, uint256 amount, uint256 shares);
    event WithdrawalCancelled(uint256 indexed requestId);
    event MemberAdded(address indexed member);
    event MemberRemoved(address indexed member);
    event MinContributionUpdated(uint256 newMinContribution);
    event YieldHarvested(address indexed vault, uint256 amount, uint256 timestamp);
    event VaultAdded(address indexed vault, address indexed asset);
    event VaultRemoved(address indexed vault);

    event JoinRequestSent(address indexed requester, uint256 requestId, uint256 groupId);
    event JoinRequestStatusUpdated(
        address indexed requester, uint256 groupId, uint256 joinRequestId, string updatedJoinRequestStatus
    );
    /// @custom:oz-upgrades-unsafe-allow constructor

    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory _name,
        uint256 _minContribution,
        address[] memory signers,
        uint256 _minSignatures,
        address creator
    ) public initializer {
        name = _name;
        minContribution = _minContribution; //1e10 
        minSignatures = _minSignatures;

        // Setup roles
        _grantRole(DEFAULT_ADMIN_ROLE, creator);
        _grantRole(ADMIN_ROLE, creator);
        _grantRole(MEMBER_ROLE, creator);
        isActiveMember[creator] = true;

        for (uint256 i = 0; i < signers.length; i++) {
            _grantRole(ADMIN_ROLE, signers[i]);
            _grantRole(MEMBER_ROLE, signers[i]);
            isActiveMember[signers[i]] = true;
        }

        _setRoleAdmin(MEMBER_ROLE, ADMIN_ROLE); //gives "ADMIN_ROLE" power to assign "MEMBER_ROLE" to addresses

        // Deploy vault for new group
        groupVault = new HifadhiGroupVault(address(this), address(0));  // addr(0) allows the group to configure the asset later via (function x()) flexibility in asset selection.

        // Initialize members array
        groupMembers.push(creator);
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] != creator) {
                // Avoid duplicate entries
                groupMembers.push(signers[i]);
            }
        }
    }

    modifier onlyMember() {
        require(hasRole(MEMBER_ROLE, msg.sender), "Caller is not a member");
        require(isActiveMember[msg.sender], "Member is not active");
        _;
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Caller is not an admin");
        _;
    }

    /**
     * @dev Add a new Beefy vault to the group
     * @param vaultAddress Address of the Beefy vault to add
     */
    function addVault(address vaultAddress) external onlyAdmin {
        require(vaultAddress != address(0), "Invalid vault address");
        require(!vaults[vaultAddress].isActive, "Vault already active");

        // Get the underlying asset from the Beefy vault
        address asset = IBeefyWrapper(vaultAddress).asset();
        require(asset != address(0), "Invalid asset");

        // Add vault to active vaults
        vaults[vaultAddress] =
            VaultInfo({vaultAddress: vaultAddress, asset: asset, totalDeposited: 0, totalShares: 0, isActive: true});

        activeVaults.push(vaultAddress);

        // Approve asset spending for this vault
        IERC20(asset).approve(vaultAddress, type(uint256).max);

        emit VaultAdded(vaultAddress, asset);
    }

    /**
     * @dev Remove a Beefy vault from the group
     * @param vaultAddress Address of the Beefy vault to remove
     */
    function removeVault(address vaultAddress) external onlyAdmin {
        require(vaults[vaultAddress].isActive, "Vault not active");
        require(vaults[vaultAddress].totalDeposited == 0, "Vault has deposits");

        // Mark vault as inactive
        vaults[vaultAddress].isActive = false;

        // Remove from active vaults array
        for (uint256 i = 0; i < activeVaults.length; i++) {
            if (activeVaults[i] == vaultAddress) {
                activeVaults[i] = activeVaults[activeVaults.length - 1];
                activeVaults.pop();
                break;
            }
        }

        // Revoke approval
        IERC20(vaults[vaultAddress].asset).approve(vaultAddress, 0);

        emit VaultRemoved(vaultAddress);
    }
    
    /**
     * @dev Deposit funds into a specific vault
     * @param vaultAddress Address of the vault to deposit into
     * @param amount Amount of tokens to deposit
     */
    function deposit(address vaultAddress, uint256 amount) external nonReentrant whenNotPaused onlyMember {
        require(amount >= minContribution, "Amount below minimum");
        require(vaults[vaultAddress].isActive, "Vault not active");

        VaultInfo storage vaultInfo = vaults[vaultAddress];
        IBeefyWrapper vault = IBeefyWrapper(vaultAddress);
        address asset = vaultInfo.asset;

        // Check deposit cap
        require(amount <= vault.maxDeposit(address(this)), "Exceeds max deposit");

        // Transfer assets from user
        uint256 balanceBefore = IERC20(asset).balanceOf(address(this));
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualDeposit = IERC20(asset).balanceOf(address(this)) - balanceBefore;

        // Deposit into Beefy Vault
        uint256 sharesBefore = vault.previewDeposit(actualDeposit);
        uint256 shares = vault.deposit(actualDeposit, address(this));
        require(shares >= sharesBefore, "Shares too low");


        // Update state
        userVaultDeposits[msg.sender][vaultAddress] += actualDeposit;
        userVaultShares[msg.sender][vaultAddress] += shares;
        vaultInfo.totalDeposited += actualDeposit;
        vaultInfo.totalShares += shares;
        totalDeposited += actualDeposit;

        emit Deposited(msg.sender, vaultAddress, actualDeposit, shares);
    }

    /**
     * @dev Request a withdrawal from a specific vault
     * @param vaultAddress Address of the vault to withdraw from
     * @param amount Amount of tokens to withdraw
     */
    function requestWithdrawal(address vaultAddress, uint256 amount) external nonReentrant onlyMember {
        require(vaults[vaultAddress].isActive, "Vault not active");
        require(amount <= userVaultDeposits[msg.sender][vaultAddress], "Insufficient balance");

        _withdrawalIds += 1;
        uint256 requestId = _withdrawalIds;

        WithdrawalRequest storage request = withdrawalRequests[requestId];
        request.requester = msg.sender;
        request.amount = amount;
        request.vaultAddress = vaultAddress;
        request.signaturesRequired = minSignatures;
        request.signaturesReceived = 0;
        request.executed = false;
        request.cancelled = false;

        emit WithdrawalRequested(requestId, msg.sender, vaultAddress, amount);
    }

    /**
     * @dev Approve a withdrawal request
     * @param requestId ID of the withdrawal request
     */
    function approveWithdrawal(uint256 requestId) external nonReentrant onlyAdmin {
        WithdrawalRequest storage request = withdrawalRequests[requestId];

        require(!request.executed, "Already executed");
        require(!request.cancelled, "Already cancelled");
        require(!request.hasApproved[msg.sender], "Already approved");

        request.hasApproved[msg.sender] = true;
        request.signaturesReceived += 1;

        emit WithdrawalApproved(requestId, msg.sender);

        if (request.signaturesReceived >= request.signaturesRequired) {
            _executeWithdrawal(requestId);
        }
    }

    /**
     * @dev Cancel a withdrawal request
     * @param requestId ID of the withdrawal request
     */
    function cancelWithdrawal(uint256 requestId) external {
        WithdrawalRequest storage request = withdrawalRequests[requestId];
        require(msg.sender == request.requester || hasRole(ADMIN_ROLE, msg.sender), "Not authorized");
        require(!request.executed, "Already executed");
        require(!request.cancelled, "Already cancelled");

        request.cancelled = true;
        emit WithdrawalCancelled(requestId);
    }

    /**
     * @dev Execute a withdrawal once enough approvals are received
     * @param requestId ID of the withdrawal request
     */
    function _executeWithdrawal(uint256 requestId) internal {
        WithdrawalRequest storage request = withdrawalRequests[requestId];
        require(!request.executed, "Already executed");
        require(!request.cancelled, "Cancelled");

        address vaultAddress = request.vaultAddress;
        VaultInfo storage vaultInfo = vaults[vaultAddress];
        require(vaultInfo.isActive, "Vault not active");

        IBeefyWrapper vault = IBeefyWrapper(vaultAddress);

        // Calculate shares to withdraw
        uint256 userShare = (request.amount * userVaultShares[request.requester][vaultAddress])
            / userVaultDeposits[request.requester][vaultAddress];
        require(userShare <= userVaultShares[request.requester][vaultAddress], "Insufficient shares");

        // Withdraw to the group vault
        uint256 sharesRedeemed = vault.withdraw(request.amount, address(groupVault), address(this));  

        // Notify vault of received funds and create distribution
        groupVault.receiveFunds(request.amount);

        address[] memory members = getActiveMembers();
        uint256[] memory shares = calculateMemberShares(members, request.amount);
        groupVault.createDistribution(members, shares);

        // Update state
        userVaultDeposits[request.requester][vaultAddress] -= request.amount;
        userVaultShares[request.requester][vaultAddress] -= sharesRedeemed;
        vaultInfo.totalDeposited -= request.amount;
        vaultInfo.totalShares -= sharesRedeemed;
        totalDeposited -= request.amount;
 
        request.executed = true;

        emit WithdrawalExecuted(requestId, address(groupVault), request.amount, sharesRedeemed);
    }

    /**
     * @dev Calculate shares for each member based on their deposits
     */
    function calculateMemberShares(address[] memory members, uint256 totalAmount)
        internal
        view
        returns (uint256[] memory)
    {
        uint256[] memory shares = new uint256[](members.length);

        for (uint256 i = 0; i < members.length; i++) {
            // Calculate based on total deposits across all vaults
            uint256 memberTotalDeposits = 0;
            for (uint256 j = 0; j < activeVaults.length; j++) {
                address vaultAddress = activeVaults[j];
                memberTotalDeposits += userVaultDeposits[members[i]][vaultAddress];
            }

           shares[i] = totalDeposited > 0 ? (memberTotalDeposits * totalAmount) / totalDeposited : 0;   //affected line
        }

        return shares;
    }

    /**
     * @dev Get all active members of the group
     */
    function getActiveMembers() public view returns (address[] memory) {
        // Count active members first
        uint256 activeCount = 0;
        for (uint256 i = 0; i < groupMembers.length; i++) {
            if (isActiveMember[groupMembers[i]]) {
                activeCount++;
            }
        }

        // Create array of exact size needed
        address[] memory activeMembers = new address[](activeCount);
        uint256 index = 0;

        // Fill array with active members
        for (uint256 i = 0; i < groupMembers.length; i++) {
            if (isActiveMember[groupMembers[i]]) {
                activeMembers[index] = groupMembers[i];
                index++;
            }
        }

        return activeMembers;
    }

    /**
     * @dev Sends request to join a particular group (from ui?)
     * @param _groupId Id of group they want to join
     */
    function requestToJoinGroupX(uint256 _groupId) public {
        //check inputs
        //is user currently a member ?
        require(msg.sender != address(0), "ZeroAddressNotAllowed");
        //user not already a member
        require(!hasRole(MEMBER_ROLE, msg.sender), "AlreadyMember");
        // Check for existing pending request
        require(!hasPendingRequest(_groupId, msg.sender), "AlreadyRequested");

        _nextRequestId[_groupId]++;
        uint256 _joinRequestId = _nextRequestId[_groupId];

        //create a join request but now for this group
        groupJoinRequests[_groupId][_joinRequestId] = JoinRequestDetails({
            requester: msg.sender,
            groupId: _groupId,
            currTStamp: block.timestamp,
            status: "PENDING",
            joinRequestId: _joinRequestId
        });
        emit JoinRequestSent(msg.sender, _joinRequestId, _groupId);
    }

    // Helper function to check for pending requests
    function hasPendingRequest(uint256 _groupId, address _user) public view returns (bool) {
        for (uint256 i = 1; i <= _nextRequestId[_groupId]; i++) {
            if (
                groupJoinRequests[_groupId][i].requester == _user
                    && keccak256(bytes(groupJoinRequests[_groupId][i].status)) == keccak256(bytes("PENDING"))
            ) {
                return true;
            }
        }
        return false;
    }

    //approve request status -> Decline or Accept Member to Join
    function SetJoinStatus(address _requester, uint256 _groupId, uint256 _joinRequestId, string memory _status)
        external
        onlyAdmin
    {
        //Input Validation
        require(_requester != address(0), "ReallyZeroAddressNotAllowed");

        JoinRequestDetails storage _groupJoinRequest = groupJoinRequests[_groupId][_joinRequestId];

        //Validate request exists, matches request  & is pending
        require(_groupJoinRequest.requester == _requester, "InvalidRequest");
        require(keccak256(bytes(_groupJoinRequest.status)) == keccak256(bytes("PENDING")), "InvalidStatus");

        _groupJoinRequest.status = _status;

        if (keccak256(bytes(_status)) == keccak256(bytes("APPROVED"))) {
            require(!hasRole(MEMBER_ROLE, _requester), "Alreadyamember");
            _grantRole(MEMBER_ROLE, _requester);
            groupMembers.push(_requester);
            isActiveMember[_requester] = true;
            emit MemberAdded(_requester);
        }
        //Emit appropriate event
        emit JoinRequestStatusUpdated(_requester, _groupId, _joinRequestId, _status);
    }

    function getJoinRequestStatus(uint256 _groupId, uint256 _joinRequestId) external view returns (string memory) {
        JoinRequestDetails storage request = groupJoinRequests[_groupId][_joinRequestId];
        require(request.joinRequestId == _joinRequestId, "RequestNotFoundOrDoesNotExist");
        return request.status;
    }

    function getJoinRequestDetails(uint256 _groupId, uint256 _joinRequestId)
        external
        view
        returns (address requester, uint256 groupId, uint256 currTStamp, string memory _status, uint256 joinRequestId)
    {
        require(_joinRequestId <= _nextRequestId[_groupId], "Invalid request ID");

        JoinRequestDetails storage joinRequestDetails = groupJoinRequests[_groupId][_joinRequestId];
        return (
            joinRequestDetails.requester,
            joinRequestDetails.groupId,
            joinRequestDetails.currTStamp,
            joinRequestDetails.status,
            joinRequestDetails.joinRequestId
        );
    }
    /**
     * @dev Add a new member to the group
     * @param member Address of the new member
     */

    function addMember(address member) external onlyAdmin {
        require(!hasRole(MEMBER_ROLE, member), "Already a member");
        groupMembers.push(member);
        _grantRole(MEMBER_ROLE, member);
        isActiveMember[member] = true;
        emit MemberAdded(member);
    }

    /**
     * @dev Remove a member from the group
     * @param member Address of the member to remove
     */
    function removeMember(address member) external onlyAdmin {
        require(hasRole(MEMBER_ROLE, member), "Not a member");

        // Check if member has deposits in any vault
        bool hasDeposits = false;
        for (uint256 i = 0; i < activeVaults.length; i++) {
            if (userVaultDeposits[member][activeVaults[i]] > 0) {
                hasDeposits = true;
                break;
            }
        }

        require(!hasDeposits, "Member has deposits");
        isActiveMember[member] = false;
        emit MemberRemoved(member);
    }

    /**
     * @dev Update minimum contribution amount
     * @param _minContribution New minimum contribution amount
     */
    function updateMinContribution(uint256 _minContribution) external onlyAdmin {
        minContribution = _minContribution;
        emit MinContributionUpdated(_minContribution);
    }

    /**
     * @dev Harvests yield for the group from underlying Beefy strategy
     * @param vaultAddress Address of the vault to harvest yield from
     */
    function harvestYield(address vaultAddress) external onlyAdmin {
        require(vaults[vaultAddress].isActive, "Vault not active");

        // This would need to interact with the specific Beefy vault
        // Some vaults auto-compound, others may need manual harvesting
        // Implementation depends on the specific vault being used

        uint256 beforeBalance = IERC20(vaults[vaultAddress].asset).balanceOf(address(this));
        // Call harvest function if available
        // For auto-compounding vaults, this might not be necessary

        uint256 afterBalance = IERC20(vaults[vaultAddress].asset).balanceOf(address(this));
        uint256 harvestedAmount = afterBalance - beforeBalance;

        if (harvestedAmount > 0) {
            emit YieldHarvested(vaultAddress, harvestedAmount, block.timestamp);
        }
    }

    /**
     * @dev Pause the contract
     */
    function pause() external onlyAdmin {
        _pause();
    }

    /**
     * @dev Unpause the contract
     */
    function unpause() external onlyAdmin {
        _unpause();
    }

    /**
     * @dev Get withdrawal request details
     */
    function getWithdrawalRequest(uint256 requestId)
        external
        view
        returns (
            address requester,
            uint256 amount,
            address vaultAddress,
            uint256 signaturesRequired,
            uint256 signaturesReceived,
            bool executed,
            bool cancelled
        )
    {
        WithdrawalRequest storage request = withdrawalRequests[requestId];
        return (
            request.requester,
            request.amount,
            request.vaultAddress,
            request.signaturesRequired,
            request.signaturesReceived,
            request.executed,
            request.cancelled
        );
    }

    /**
     * @dev Check if a withdrawal has been approved by a specific address
     */
    function hasApprovedWithdrawal(uint256 requestId, address approver) external view returns (bool) {
        return withdrawalRequests[requestId].hasApproved[approver];
    }

    /**
     * @dev Get user's current value in a specific vault (including yield)
     */
    function getUserCurrentValue(address user, address vaultAddress) external view returns (uint256) {
        if (userVaultShares[user][vaultAddress] == 0) return 0;

        IBeefyWrapper vault = IBeefyWrapper(vaultAddress);
        return vault.convertToAssets(userVaultShares[user][vaultAddress]);
    }

    /**
     * @dev Get user's earned yield in a specific vault
     */
    function getUserEarnedYield(address user, address vaultAddress) external view returns (uint256) {
        if (userVaultShares[user][vaultAddress] == 0) return 0;

        IBeefyWrapper vault = IBeefyWrapper(vaultAddress);
        uint256 currentValue = vault.convertToAssets(userVaultShares[user][vaultAddress]);

        return currentValue > userVaultDeposits[user][vaultAddress]
            ? currentValue - userVaultDeposits[user][vaultAddress]
            : 0;
    }

    /**
     * @dev Get total group value in a specific vault (including yield)
     */
    function getVaultCurrentValue(address vaultAddress) external view returns (uint256) {
        VaultInfo storage vaultInfo = vaults[vaultAddress];
        if (vaultInfo.totalShares == 0) return 0;

        IBeefyWrapper vault = IBeefyWrapper(vaultAddress);
        return vault.convertToAssets(vaultInfo.totalShares);
    }

    /**
     * @dev Get total group earned yield in a specific vault
     */
    function getVaultEarnedYield(address vaultAddress) external view returns (uint256) {
        VaultInfo storage vaultInfo = vaults[vaultAddress];
        if (vaultInfo.totalShares == 0) return 0;

        IBeefyWrapper vault = IBeefyWrapper(vaultAddress);
        uint256 currentValue = vault.convertToAssets(vaultInfo.totalShares);

        return currentValue > vaultInfo.totalDeposited ? currentValue - vaultInfo.totalDeposited : 0;
    }

    /**
     * @dev Get all active vaults
     */
    function getActiveVaults() external view returns (address[] memory) {
        return activeVaults;
    }

    /**
     * @dev Get user's total deposits across all vaults
     */
    function getUserTotalDeposits(address user) external view returns (uint256) {
        uint256 totalUserDeposits = 0;
        for (uint256 i = 0; i < activeVaults.length; i++) {
            totalUserDeposits += userVaultDeposits[user][activeVaults[i]];
        }
        return totalUserDeposits;
    }

    /**
     * @dev Get total group value across all vaults (including yield)
     */
    function getGroupTotalValue() external view returns (uint256) {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < activeVaults.length; i++) {
            address vaultAddress = activeVaults[i];
            VaultInfo storage vaultInfo = vaults[vaultAddress];

            if (vaultInfo.totalShares > 0) {
                IBeefyWrapper vault = IBeefyWrapper(vaultAddress);
                totalValue += vault.convertToAssets(vaultInfo.totalShares);
            }
        }
        return totalValue;
    }
}
