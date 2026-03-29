// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProtocolGuardian
 * @dev Onchain executor for the AI Guardian Agent.
 *      Holds PAUSER_ROLE on the monitored protocol.
 *      Only the guardian EOA (AI agent hot wallet) can trigger pause.
 *      Only the owner multisig can unpause and rotate guardian.
 *
 *      Security properties:
 *      - Confidence must be >= 75 to pause (prevents low-confidence false positives)
 *      - Guardian key can be rotated without redeployment
 *      - Guardian can be deactivated by owner for emergency key rotation
 *      - All actions emit events with full rationale onchain
 */

interface IPausable {
    function pause() external;
    function unpause() external;
}

contract ProtocolGuardian {
    address public guardian;     // AI agent hot wallet
    address public protocol;     // monitored contract
    address public owner;        // deployer / multisig

    bool public active = true;
    uint256 public pauseCount;
    uint256 public constant MIN_CONFIDENCE = 75;

    struct PauseRecord {
        uint256 timestamp;
        string attackType;
        uint8 confidence;
        address suspectedAttacker;
        uint256 estimatedLossUsd;
        string rationale;
    }

    mapping(uint256 => PauseRecord) public pauseHistory;

    event ThreatDetected(
        uint256 indexed pauseId,
        string attackType,
        uint8 confidence,
        address indexed suspectedAttacker,
        uint256 estimatedLossUsd,
        string rationale
    );
    event ProtocolPaused(uint256 indexed pauseId, uint256 timestamp);
    event ProtocolUnpaused(address indexed by, uint256 timestamp);
    event GuardianRotated(address indexed oldGuardian, address indexed newGuardian);
    event GuardianDeactivated(uint256 timestamp);
    event GuardianActivated(uint256 timestamp);

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Caller is not guardian");
        require(active, "Guardian is deactivated");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    constructor(address _guardian, address _protocol) {
        guardian = _guardian;
        protocol = _protocol;
        owner = msg.sender;
    }

    /**
     * @notice Called by the AI agent when it detects a threat with sufficient confidence.
     * @param attackType  Short string: "flash_loan_price_manipulation", "reentrancy", etc.
     * @param confidence  0-100 score from the AI reasoning layer.
     * @param suspectedAttacker  Address identified as attacker (or address(0) if unknown).
     * @param estimatedLossUsd  Estimated USD value at risk (0 if unknown).
     * @param rationale  Plain-English explanation from the AI agent.
     */
    function emergencyPause(
        string calldata attackType,
        uint8 confidence,
        address suspectedAttacker,
        uint256 estimatedLossUsd,
        string calldata rationale
    ) external onlyGuardian {
        require(confidence >= MIN_CONFIDENCE, "Confidence below threshold");
        require(bytes(attackType).length > 0, "Attack type required");
        require(bytes(rationale).length > 0, "Rationale required");

        pauseCount++;
        uint256 pauseId = pauseCount;

        pauseHistory[pauseId] = PauseRecord({
            timestamp: block.timestamp,
            attackType: attackType,
            confidence: confidence,
            suspectedAttacker: suspectedAttacker,
            estimatedLossUsd: estimatedLossUsd,
            rationale: rationale
        });

        emit ThreatDetected(
            pauseId,
            attackType,
            confidence,
            suspectedAttacker,
            estimatedLossUsd,
            rationale
        );
        emit ProtocolPaused(pauseId, block.timestamp);

        IPausable(protocol).pause();
    }

    function unpause() external onlyOwner {
        IPausable(protocol).unpause();
        emit ProtocolUnpaused(msg.sender, block.timestamp);
    }

    function rotateGuardian(address newGuardian) external onlyOwner {
        require(newGuardian != address(0), "Invalid guardian");
        emit GuardianRotated(guardian, newGuardian);
        guardian = newGuardian;
    }

    function deactivate() external onlyOwner {
        active = false;
        emit GuardianDeactivated(block.timestamp);
    }

    function reactivate() external onlyOwner {
        active = true;
        emit GuardianActivated(block.timestamp);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }

    function getPauseRecord(uint256 pauseId) external view returns (PauseRecord memory) {
        return pauseHistory[pauseId];
    }
}
