// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Interface for the Malicious Code Detection Service Manager
 * @notice This interface defines the functions for interacting with the EigenLayer AVS for malicious code detection
 */
interface IMaliciousCodeDetectionServiceManager {
    /**
     * @notice Task structure for malicious code detection requests
     * @param contractAddress Address of the contract to analyze
     * @param taskCreatedBlock Block number when the task was created
     */
    struct Task {
        address contractAddress;
        uint32 taskCreatedBlock;
    }

    /**
     * @notice Creates a new task for malicious code detection
     * @param contractAddress Address of the contract to analyze
     * @return task The created task
     */
    function createNewTask(address contractAddress) external returns (Task memory);

    /**
     * @notice Checks if a task has been responded to
     * @param taskIndex Index of the task to check
     * @return True if the task has been responded to, false otherwise
     */
    function taskWasResponded(uint32 taskIndex) external view returns (bool);

    /**
     * @notice Gets the result of a malicious code detection task
     * @param taskIndex Index of the task to get the result for
     * @return True if malicious code was detected, false otherwise
     */
    function getTaskResult(uint32 taskIndex) external view returns (bool);

    /**
     * @notice Submit a response for a task
     * @param taskIndex Index of the task to respond to
     * @param result True if malicious code was detected, false otherwise
     */
    function respondToTask(uint32 taskIndex, bool result) external;
}
