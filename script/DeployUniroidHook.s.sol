// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {UniroidHook} from "../src/UniroidHook.sol";

/**
 * @title DeployUniroidHook
 * @notice Script to deploy the UniroidHook contract
 * @dev Uses a pre-mined salt from the MineUniroidHookAddress script
 */
contract DeployUniroidHook is Script {
    // CREATE2 factory address - standard across all EVM chains
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    
    // Sepolia Pool Manager address
    address constant POOL_MANAGER_SEPOLIA = 0xE03A1074c86CFeDd5C142C4F04F1a1536e203543;

    function run() external {
        // Get private key from environment variable
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);
        
        // Log deployment information
        console.log("Deploying UniroidHook contract to Sepolia");
        console.log("Deployer address:", deployer);
        
        // Get the pool manager address from environment variable for Sepolia
        address poolManagerAddress = POOL_MANAGER_SEPOLIA;
        console.log("Using Sepolia Pool Manager address:", poolManagerAddress);
        
        // Get the salt from environment variable or use the mined salt
        bytes32 salt = bytes32(0x0000000000000000000000000000000000000000000000000000000000002f4c);
        console.log("Using salt:", vm.toString(salt));
        
        // Start the broadcast to record and send transactions
        vm.startBroadcast(privateKey);
        
        // Deploy the hook using CREATE2 with the mined salt
        UniroidHook hook = new UniroidHook{salt: salt}(
            IPoolManager(poolManagerAddress),
            "Uniroid Token",
            "UNIROID",
            deployer
        );
        
        // Log the deployed address
        address deployedAddress = address(hook);
        console.log("Deployed hook address:", deployedAddress);
        
        // End the broadcast
        vm.stopBroadcast();
        
        console.log("UniroidHook deployed successfully to Sepolia!");
    }
}

// forge script script/DeployUniroidHook.s.sol --rpc-url https://eth-sepolia.public.blastapi.io --broadcast