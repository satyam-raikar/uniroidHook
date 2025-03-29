// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title TestLocalDeployment
 * @notice Script to test the address mining and deployment process on a local network
 * @dev This script deploys a Pool Manager, mines a hook address, and deploys the UniroidHook contract
 *
 * @dev Usage Instructions:
 * 1. Run this script to test the hook mining and deployment process locally:
 *    forge script script/TestLocalDeployment.s.sol -vvv
 * 
 * 2. This script performs the following steps:
 *    - Deploys a local Pool Manager
 *    - Mines a salt value to generate a hook address with the correct flags
 *    - Deploys the UniroidHook contract using CREATE2 with the mined salt
 *    - Verifies that the deployed address matches the expected address
 *    - Verifies that the hook address has the correct flags
 *
 * 3. This is useful for testing the deployment process before deploying to a testnet or mainnet
 */

import {Script, console} from "forge-std/Script.sol";
import {Test} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {HookMiner} from "v4-periphery/src/utils/HookMiner.sol";
import {UniroidHook} from "../src/UniroidHook.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title TestLocalDeployment
 * @notice Script to test the address mining and deployment process on a local network
 * @dev This script deploys a Pool Manager, mines a hook address, and deploys the UniroidHook contract
 */
contract TestLocalDeployment is Script, Test, Deployers {
    // CREATE2_FACTORY is already defined in forge-std/Base.sol
    
    function run() external {
        // Get private key from environment variable
        uint256 privateKey;
        try vm.envUint("PRIVATE_KEY") returns (uint256 pk) {
            privateKey = pk;
        } catch {
            // Fallback to a default private key for testing if not provided
            console.log("PRIVATE_KEY environment variable not found, using default test key");
            privateKey = 0x88d0d26ebc28a68cc420ac2ca9cb31a0108fcebd5c1ca49fbf5debbd694e4699; //random testing private key
        }
        
        address deployer = vm.addr(privateKey);
        
        console.log("=== Local Deployment Test ===");
        console.log("Deployer address:", deployer);
        
        // Deploy PoolManager and Router contracts using Deployers
        deployFreshManagerAndRouters();
        console.log("Pool Manager deployed at:", address(manager));
        
        // Define hook flags for UniroidHook
        // These flags must be encoded in the last 2 bytes of the hook address
        uint160 flags = uint160(
            Hooks.AFTER_ADD_LIQUIDITY_FLAG | 
            Hooks.AFTER_SWAP_FLAG | 
            Hooks.BEFORE_INITIALIZE_FLAG | 
            Hooks.BEFORE_SWAP_FLAG | 
            Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG
        );
        
        console.log("Hook flags (decimal):", uint256(flags));
        console.log("Hook flags (binary):", uint256ToString(uint256(flags), 2));
        
        // Prepare constructor arguments
        bytes memory constructorArgs = abi.encode(
            IPoolManager(address(manager)),
            "Uniroid Token",
            "UNIROID",
            deployer
        );
        
        console.log("Mining hook address...");
        
        // Mine a salt that will produce a hook address with the correct flags
        // HookMiner.find will search for a salt that produces an address where
        // the last 2 bytes match our flags pattern
        (address hookAddress, bytes32 salt) = HookMiner.find(
            CREATE2_FACTORY,
            flags,
            type(UniroidHook).creationCode,
            constructorArgs
        );
        
        console.log("Mining completed!");
        console.log("Expected hook address:", hookAddress);
        console.log("Hook address last 2 bytes (hex):", toHexString(uint160(hookAddress) & 0xFFFF, 2));
        console.log("Mined salt:", vm.toString(salt));
        
        // Deploy the hook using the mined salt
        vm.startBroadcast(privateKey);
        
        // Deploy the contract using the create2 opcode
        bytes memory bytecode = abi.encodePacked(type(UniroidHook).creationCode, constructorArgs);
        address deployedAddress;
        
        // Use inline assembly to deploy with create2
        assembly {
            deployedAddress := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        
        vm.stopBroadcast();
        
        console.log("Deployed hook address:", deployedAddress);
        console.log("Deployed address last 2 bytes (hex):", toHexString(uint160(deployedAddress) & 0xFFFF, 2));
        
        // Verify the hook flags
        bool hasCorrectFlags = verifyHookFlags(deployedAddress, hookAddress);
        
        console.log("=== Verification Results ===");
        if (deployedAddress == hookAddress) {
            console.log("SUCCESS: Deployed address matches expected address");
        } else {
            console.log("ERROR: Deployed address does not match expected address");
            console.log("  Expected:", hookAddress);
            console.log("  Actual:", deployedAddress);
        }
        
        if (hasCorrectFlags) {
            console.log("SUCCESS: Hook address has correct flags");
        } else {
            console.log("ERROR: Hook address does not have correct flags");
            console.log("  Expected address:", hookAddress);
            console.log("  Actual address:", deployedAddress);
        }
        
        console.log("=== Test Completed ===");
    }
    
    // Helper function to verify hook flags according to Uniswap V4 documentation
    function verifyHookFlags(address deployedAddress, address expectedAddress) internal pure returns (bool) {
        // According to Uniswap V4 documentation, the hook flags are encoded in the address
        // The HookMiner.find function already ensures that the address has the correct flags
        // So we just need to check if the deployed address matches the expected address
        return deployedAddress == expectedAddress;
    }
    
    // Helper function to convert uint to binary string
    function uint256ToString(uint256 value, uint8 base) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        
        uint256 temp = value;
        uint256 digits;
        
        while (temp != 0) {
            digits++;
            temp /= base;
        }
        
        bytes memory buffer = new bytes(digits);
        
        while (value != 0) {
            digits -= 1;
            // Convert to ASCII character
            uint8 ascii = uint8(48 + uint8(value % base));
            if (base > 10 && ascii > 57) {
                ascii = ascii + 7; // 'A'-'F' is 65-70
            }
            buffer[digits] = bytes1(ascii);
            value /= base;
        }
        
        return string(buffer);
    }
    
    // Helper function to convert uint to hex string with padding
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length);
        for (uint256 i = 2 * length; i > 0; i--) {
            // Convert to ASCII character
            uint8 ascii = uint8(48 + uint8(value % 16));
            if (ascii > 57) {
                ascii = ascii + 39; // 'a'-'f' is 97-102
            }
            buffer[i - 1] = bytes1(ascii);
            value /= 16;
        }
        return string(abi.encodePacked("0x", buffer));
    }
}
