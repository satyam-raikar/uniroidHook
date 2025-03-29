// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";

/**
 * @title DeployPoolManagerHolesky
 * @notice Script to deploy Uniswap V4 Pool Manager and test contracts on Holesky testnet
 * @dev This script deploys the core Uniswap V4 contracts needed for hook development
 * 
 * @dev Usage Instructions:
 * 1. Make sure you have PRIVATE_KEY set in your .env file
 * 2. Run the script with:
 *    forge script script/DeployPoolManagerHolesky.s.sol --rpc-url <HOLESKY_RPC_URL> --broadcast -vvv
 * 
 * 3. After deployment, add the Pool Manager address to your .env file:
 *    POOL_MANAGER_ADDRESS_HOLESKY=<deployed_address>
 */
contract DeployPoolManagerHolesky is Script {
    function run() external {
        // Get private key from environment variable
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);
        
        console.log("=== Deploying Uniswap V4 Pool Manager to Holesky ===");
        console.log("Deployer address:", deployer);
        
        // Start the broadcast to record and send transactions
        vm.startBroadcast(privateKey);
        
        // Deploy the Pool Manager directly
        // The PoolManager constructor takes a single uint256 parameter for protocol fee
        PoolManager poolManager = new PoolManager(deployer);
        // End the broadcast
        vm.stopBroadcast();
        
        console.log("Pool Manager deployed at:", address(poolManager));
        
        console.log("=== Deployment Complete ===");
        console.log("Add this to your .env file:");
        console.log("POOL_MANAGER_ADDRESS_HOLESKY=", address(poolManager));
        
        // Additional information for using the deployed contracts
        console.log("");
        console.log("=== Usage Information ===");
        console.log("1. Update MineHookAddress.s.sol with this Pool Manager address");
        console.log("2. Run MineHookAddress.s.sol to generate a salt for your hook");
        console.log("3. Create DeployUniroidHookHolesky.s.sol based on DeployUniroidHook.s.sol");
    }
}


// Deploy to Holesky testnet
// forge script script/DeployPoolManagerHolesky.s.sol --rpc-url https://1rpc.io/holesky -vvvv
// forge script script/DeployPoolManagerHolesky.s.sol --rpc-url https://1rpc.io/holesky --broadcast -vvv