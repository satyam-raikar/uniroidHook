// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Interface for the Vesting Verification Service Manager
 * @notice This interface defines the functions for interacting with the EigenLayer AVS for vesting verification
 */
interface IVestingVerificationServiceManager {
    /**
     * @notice Task structure for vesting verification requests
     * @param tokenAddress Address of the token to analyze for vesting
     * @param projectAddress Address of the project to check for vesting
     * @param taskCreatedBlock Block number when the task was created
     */
    struct Task {
        address tokenAddress;
        address projectAddress;
        uint32 taskCreatedBlock;
    }

    /**
     * @notice Creates a new task for vesting verification
     * @param tokenAddress Address of the token to analyze
     * @param projectAddress Address of the project to check
     * @return task The created task
     */
    function createNewTask(address tokenAddress, address projectAddress) external returns (Task memory);

    /**
     * @notice Checks if a task has been responded to
     * @param taskIndex Index of the task to check
     * @return True if the task has been responded to, false otherwise
     */
    function taskWasResponded(uint32 taskIndex) external view returns (bool);

    /**
     * @notice Gets the result of a vesting verification task
     * @param taskIndex Index of the task to get the result for
     * @return True if valid vesting or token lock was detected, false otherwise
     */
    function getTaskResult(uint32 taskIndex) external view returns (bool);

    /**
     * @notice Submit a response for a vesting verification task
     * @param taskIndex Index of the task to respond to
     * @param result True if valid vesting or token lock was detected, false otherwise
     */
    function respondToTask(uint32 taskIndex, bool result) external;
}
