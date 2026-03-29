// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

// Interface must be declared at file level — Solidity does not allow nested interfaces
interface IFlashLoanReceiver {
    function executeOperation(
        uint256 amount,
        uint256 fee,
        bytes calldata params
    ) external returns (bool);
}

/**
 * @title MockLendingPool
 * @dev Simplified lending pool for Protocol Guardian demo.
 *      Supports flash loans, deposits, and borrowing.
 *      Has a PAUSER_ROLE that the Guardian contract holds.
 */
contract MockLendingPool is Pausable, AccessControl {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    uint256 public totalLiquidity;

    // Simplified price oracle (manipulable for demo)
    uint256 public assetPrice = 2000e18; // $2000 per ETH in 18 decimals
    address public oracleUpdater;

    event Deposit(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event FlashLoan(address indexed borrower, uint256 amount, uint256 fee);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);
    event ProtocolPaused(address indexed by, string reason);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        oracleUpdater = msg.sender;
    }

    function grantPauserRole(address pauser) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(PAUSER_ROLE, pauser);
    }

    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Must deposit ETH");
        deposits[msg.sender] += msg.value;
        totalLiquidity += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function borrow(uint256 amount) external whenNotPaused {
        require(amount <= totalLiquidity / 2, "Exceeds borrow limit");
        borrows[msg.sender] += amount;
        totalLiquidity -= amount;
        payable(msg.sender).transfer(amount);
        emit Borrow(msg.sender, amount);
    }

    function repay() external payable whenNotPaused {
        require(borrows[msg.sender] > 0, "No borrow to repay");
        borrows[msg.sender] -= msg.value;
        totalLiquidity += msg.value;
        emit Repay(msg.sender, msg.value);
    }

    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata params
    ) external whenNotPaused {
        require(amount <= totalLiquidity, "Insufficient liquidity");
        uint256 fee = (amount * 9) / 10000; // 0.09% fee
        uint256 balanceBefore = address(this).balance;

        payable(receiver).transfer(amount);
        emit FlashLoan(receiver, amount, fee);

        require(
            IFlashLoanReceiver(receiver).executeOperation(amount, fee, params),
            "Flash loan failed"
        );

        require(
            address(this).balance >= balanceBefore + fee,
            "Flash loan not repaid"
        );
    }

    // Manipulable price oracle for attack demo
    function updatePrice(uint256 newPrice) external {
        require(msg.sender == oracleUpdater, "Not oracle updater");
        emit PriceUpdated(assetPrice, newPrice);
        assetPrice = newPrice;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
        emit ProtocolPaused(msg.sender, "Emergency pause triggered");
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    receive() external payable {}

    function getPoolStats() external view returns (
        uint256 liquidity,
        uint256 price,
        bool isPaused
    ) {
        return (totalLiquidity, assetPrice, paused());
    }
}
