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
import "./HifadhiGroup.sol";

/**
 * @title HifadhiContributionCycleManager
 * @dev Manages contribution cycles for a group vault.
 * @notice This contract is designed to facilitate the management of contribution cycles, the vault is used to hold and distribute group funds(managing deposits). This contract is thus in no way in a position to hold / transfer / distribute funds.
 * It allows for the creation of new cycles, cyclic tracking of deposits, and triggering of investments to a beefy vault.
 * Utilizes roles for access control, supports pausing, and is protected against reentrancy.
 *
 * @notice This contract allows the creation and management of contribution cycles, each with a unique cycle ID.
 * Cycles progress through various statuses, from pending to completed, with events emitted at key transitions.
 *
 * @dev The contract uses SafeERC20 for secure token operations and includes mappings for tracking user deposits and shares.
 * It features a constructor for setting the vault address and functions for starting new cycles and triggering investments.
 */
contract HifadhiContributionCycleManager is ReentrancyGuard, AccessControl, Pausable, Initializable {
    using SafeERC20 for IERC20;

    // Roles`   
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MEMBER_ROLE = keccak256("MEMBER_ROLE");

    address public groupVault; // Set in the constructor whenever this Contract is Invoked
    HifadhiGroup public groupVaultContract;

    enum CycleStatus {
        PENDING,
        DEPOSITING,
        INVESTMENT_TRIGGERED, // Vault - investment to beefy triggered
        YIELD_GENERATING, // Vault - yield generating in beefy
        WITHDRAWING, // Claiming period - after yield generation & funds are back in the vault.
        COMPLETED, // Cycle successfully raised funds, invested, earned yield & redistributed according to ratio shares.
        CANCELLED, // Cycle was cancelled before investment was triggered
        FAILED // Cycle failed to raise enough funds for investment / failed to stay long enough to earn yield due to user cancellation during yield generation.

    }

    struct S_CycleContainer {
        bytes32 cycleId;
        CycleStatus status;
        uint256 startTime; // start time of the contribution round
        uint256 cycleDuration; // How long the cycle should take before investment to beefy is triggered
        uint256 contributionEndTime; // expected stop time for the contribution round
        uint256 totalDepositAmount; // total amount deposited for contribution round
        uint256 investmentThresholdTrigger_p; // percentage of total deposit amount that should be reached before investment is triggered
        uint256 minimumThreshold_p; // minimum amount that should be reached before investment is triggered -- else cancel cycle 75% of targetIVAmount
        uint256 targetInvestmentAmount; // target amount to be invested in beefy vault
        uint256 targetPercentageThreshold_p; // percentage of total deposit amount that should be reached before investment is triggered - 100% by each user.
        uint256 totalInvestmentAmount; // total amount sent to beefy for contribution round, should be equal to deposit amount
        uint256 totalYieldAmount; // total reported yield from beefy from contribution round
        uint256 totalClaimableAmount; // calculated based on shares of contribution in round.

        mapping(address userAddress => uint256 depositRatio) UserToDepositShareRatio;
        bool isRatioCalculated; // set to true when a new Round is created.
    }

    bytes32[] public cyclesContainerArr; // array of all round IDs created
    mapping(bytes32  => S_CycleContainer) public CycleIdToCycleContainerStruct; // mapping of cycleId to S_CycleContainer

    event NewRoundStarted(
        bytes32 indexed cycleId,
        address indexed groupVault,
        address indexed userAddress,
        uint256 startTime,
        uint256 endTime
    );
    event DepositRecorded(
        bytes32 indexed cycleId, address indexed groupVault, address indexed userAddress, uint256 amount
    );
    event InvestmentTriggered(bytes32 indexed cycleId, uint256 totalDepositAmount);
    event RoundStatusUpdated(bytes32 indexed cycleId, CycleStatus newStatus);
    event RatiosCalculated(bytes32 cycleId); // Backend ?

    // Using the constructor to set the vault address we're going to use, starting a new cycle will be done using a separate external function
    constructor(address _groupVaultAddress) {
        require(_groupVaultAddress != address(0), "InvalidGroupVaultAddress");
        groupVault = _groupVaultAddress;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        // Ping Vault about this cycle manager 
        HifadhiGroupVault(groupVault).setCycleManager(address(this));
    }

    //HifadhiGroup public groupVaultContract = HifadhiGroup(groupVault); // Group vault contract
    /**
     * @dev internal helper function for generating random Ids using salt number
     */
    uint256 private _saltNum = 254;
    //TODO: Add MATHEMATICAL FUNCTION TO USE Z TO INCREASE RANDOMNESS
    // Utility function

    function _generateRandomIds() internal returns (bytes32) {
        bytes32 _randId =
            (keccak256(abi.encodePacked(block.timestamp, block.gaslimit, block.number, _saltNum, msg.sender)));
        _saltNum += 7;
        return _randId;
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Callerisnotanadmin");
        _;
    }

    // Internal helper function (uniswap convention) to assign the variables and  clean up new cycle creation
    function _prepareParamsForNewCycle(
        bytes32 _cycleId,
        uint256 _contributionEndTime,
        uint256 _cycleDuration,
        uint256 _targetInvestmentAmount,
        uint256 _investmentThresholdTrigger,
        uint256 _minimumThreshold
    ) internal {
        S_CycleContainer storage newCycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        newCycleContainer.cycleId = _cycleId;
        newCycleContainer.status = CycleStatus.PENDING;
        newCycleContainer.startTime = block.timestamp;
        newCycleContainer.cycleDuration = _cycleDuration;
        newCycleContainer.contributionEndTime = _contributionEndTime;
        newCycleContainer.targetInvestmentAmount = _targetInvestmentAmount;
        newCycleContainer.totalDepositAmount = 0;
        newCycleContainer.totalInvestmentAmount = 0;
        newCycleContainer.totalYieldAmount = 0;
        newCycleContainer.totalClaimableAmount = 0;
        newCycleContainer.investmentThresholdTrigger_p = _investmentThresholdTrigger;
        newCycleContainer.minimumThreshold_p = _minimumThreshold;
        newCycleContainer.targetPercentageThreshold_p = 90; // Default value, can be changed later
        newCycleContainer.isRatioCalculated = false;

        // The array for tracking 
        cyclesContainerArr.push(_cycleId);
    }

    // starting a new round: procedure
    // set start time -> now, phase -> Depositing, new round Id -> call internal fn, set target percentage threshold -> 90% default, minimum threshold 
                                // -> 75%, initialize total deposit -> 0, update mappings, set isRatiosCalculated -> false
    function startNewCycle(
        uint256 _contributionEndTime,
        uint256 _cycleDuration,
        uint256 _targetInvestmentAmount,
        uint256 _investmentThresholdTrigger,
        uint256 _minimumThreshold
    ) external onlyAdmin returns (bytes32) {
        bytes32 newCycleId = _generateRandomIds();

         // Initialize groupVaultContract if not already set
    if (address(groupVaultContract) == address(0)) {
        groupVaultContract = HifadhiGroup(groupVault);
    }
        _prepareParamsForNewCycle(
            newCycleId,
            _contributionEndTime,
            _cycleDuration,
            _targetInvestmentAmount,
            _investmentThresholdTrigger,
            _minimumThreshold
        );

        emit NewRoundStarted(newCycleId, groupVault, msg.sender, block.timestamp, _contributionEndTime);
        return newCycleId;
    }

    // Function to be used by the backend to trigger the Investment
    // TODO: Add Logic to transfer to beefy vault.
    function triggerInvestmentToBeefy(bytes32 _cycleId) external onlyAdmin {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        require(keccak256(bytes(_checkCycleStatus(_cycleId))) == keccak256(bytes("DEPOSITING")), "InvalidCycleStatus");
        require(_isCycleDurationExpired(_cycleId) == false, "CycleDurationNotExpired")  ; //should be == true, 
        require(cycleContainer.totalDepositAmount >= cycleContainer.minimumThreshold_p, "MinimumthresholdNotReached");
        require(
            cycleContainer.totalDepositAmount >= cycleContainer.investmentThresholdTrigger_p,
            "InvestmentThresholdNotReached"
        );
        require(
            cycleContainer.totalDepositAmount >= cycleContainer.targetInvestmentAmount, "TargetInvestmentNotReached"
        );

        cycleContainer.status = CycleStatus.INVESTMENT_TRIGGERED;
        emit InvestmentTriggered(_cycleId, cycleContainer.totalDepositAmount);
    }   

    function _isInvestmentThresholdMet(bytes32 _cycleId, address _vaultAddress, address _assetDeposited)
        public
        view
        returns (bool)
    {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        uint256 currDepositAmount =
            HifadhiGroupVault(_vaultAddress).getVaultCycleBalance(_assetDeposited, _vaultAddress, _cycleId);
        // Threshold is a percentage so we need to calculate the ratio of deposit to targetInvestmentAmount
        uint256 currIvRatio = (currDepositAmount * 100) / cycleContainer.targetInvestmentAmount;
        if (
            currIvRatio >= cycleContainer.minimumThreshold_p
                && currIvRatio >= cycleContainer.investmentThresholdTrigger_p
        ) {
            return true;
        }
        return false;
    }

    function _getUserZDepositRatioInCycleXVaultY(bytes32 _cycleId, address _user, address _asset, address _vaultaddress)
        public
        view
        returns (uint256)
    {
        uint256 _userDeposit  = HifadhiGroupVault(_vaultaddress).getUserDepositForCycle(_user, _cycleId);
        uint256 _totalDepositAmount =
            HifadhiGroupVault(_vaultaddress).getVaultCycleBalance(_asset, _vaultaddress, _cycleId);
        if (_totalDepositAmount == 0 || _userDeposit == 0) {
            return 0;
        }
        return ((_userDeposit * 100) / _totalDepositAmount);
    }

    function _getCycleTargetInvestmentAmt(bytes32 _cycleId) public view returns (uint256) {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        return cycleContainer.targetInvestmentAmount;
    }
    function _getCycleInvestmentThreshold(bytes32 _cycleId) public view returns (uint256) {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        return cycleContainer.investmentThresholdTrigger_p;
    }
    function _getCycleMinimumThreshold(bytes32 _cycleId) public view returns (uint256) {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        return cycleContainer.minimumThreshold_p;
    }

    function _getGroupWideCompletionRate(bytes32 _cycleId, address _vaultAddress, address _asset)
        public
        view
        returns (uint256)
    {
        uint256 cycleTargetInvestmentAmt = _getCycleTargetInvestmentAmt(_cycleId);
        uint256 _totalDepositAmount =
            HifadhiGroupVault(_vaultAddress).getVaultCycleBalance(_asset, _vaultAddress, _cycleId);
        if (_totalDepositAmount == 0) {
            return 0;
        }

        return ((_totalDepositAmount * 100) / (cycleTargetInvestmentAmt));
    }

    function _checkCycleStatus(bytes32 _cycleId) public view returns (string memory) {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];
        if (cycleContainer.status == CycleStatus.DEPOSITING) {
            return "DEPOSITING";
        } else if (cycleContainer.status == CycleStatus.PENDING) {
            return "PENDING";
        } else if (cycleContainer.status == CycleStatus.INVESTMENT_TRIGGERED) {
            return "INVESTMENT_TRIGGERED";
        } else if (cycleContainer.status == CycleStatus.YIELD_GENERATING) {
            return "YIELD_GENERATING";
        } else if (cycleContainer.status == CycleStatus.WITHDRAWING) {
            return "WITHDRAWING";
        } else if (cycleContainer.status == CycleStatus.COMPLETED) {
            return "COMPLETED";
        } else if (cycleContainer.status == CycleStatus.CANCELLED) {
            return "CANCELLED";
        } else if (cycleContainer.status == CycleStatus.FAILED) {
            return "FAILED";
        }
        return "INVALIDCYCLESTATUS";
    }

    function _isCycleDurationExpired(bytes32 _cycleId) public view returns (bool) {
        S_CycleContainer storage cycleContainer = CycleIdToCycleContainerStruct[_cycleId];

        return block.timestamp >= (cycleContainer.startTime + cycleContainer.cycleDuration);
    }
}
