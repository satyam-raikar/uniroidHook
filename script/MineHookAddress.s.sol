// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {HookMiner} from "v4-periphery/src/utils/HookMiner.sol";

import {UniroidHook} from "../src/UniroidHook.sol";

/**
 * @title MineHookAddress
 * @notice Script to mine a salt for deploying hook contracts with the correct hook flags
 * @dev Uses HookMiner to find a salt that will produce a hook address with the correct flags
 */
contract MineHookAddress is Script {
    // Network specific pool manager addresses
    address constant POOL_MANAGER_SEPOLIA = 0xE03A1074c86CFeDd5C142C4F04F1a1536e203543;
    address constant POOL_MANAGER_MAINNET = 0x0000000000000000000000000000000000000000; // Replace with actual address when available
    address constant POOL_MANAGER_GOERLI = 0x0000000000000000000000000000000000000000; // Replace with actual address when available
    address constant POOL_MANAGER_ARBITRUM = 0x0000000000000000000000000000000000000000; // Replace with actual address when available
    address constant POOL_MANAGER_HOLESKY = 0x4fdC9175Bc952e8bDCe2e8cA38d00EAa9dB9a299; // Deployed via DeployPoolManagerHolesky.s.sol
    
    // Hook configuration
    string constant TOKEN_NAME = "Uniroid Token";
    string constant TOKEN_SYMBOL = "UNIROID";

    function run() external view {
        // Define which network to use
        address poolManagerAddress = POOL_MANAGER_SEPOLIA; // Using Sepolia for deployment
        
        // Get deployer address from private key
        address deployer;
        try vm.envUint("PRIVATE_KEY") returns (uint256 privateKey) {
            deployer = vm.addr(privateKey);
            console.log("Deployer address (from PRIVATE_KEY):", deployer);
        } catch {
            // If no private key is set, use a default address
            deployer = address(this);
            console.log("No PRIVATE_KEY found in .env file, using script address as deployer:", deployer);
        }
        
        console.log("Using Pool Manager address:", poolManagerAddress);

        // Define hook flags for the hook contract
        uint160 flags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | 
            Hooks.AFTER_INITIALIZE_FLAG | 
            Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG |
            Hooks.AFTER_ADD_LIQUIDITY_FLAG | 
            Hooks.BEFORE_SWAP_FLAG | 
            Hooks.AFTER_SWAP_FLAG
        );
        
        console.log("Hook flags (decimal):", uint256(flags));
        console.log("Hook flags (binary):", uint256ToString(uint256(flags), 2));

        // Prepare constructor arguments
        bytes memory constructorArgs = abi.encode(
            IPoolManager(poolManagerAddress),
            TOKEN_NAME,
            TOKEN_SYMBOL,
            deployer
        );

        // Mine a salt that will produce a hook address with the correct flags
        console.log("Mining salt for hook contract...");
        console.log("This may take a while...");
        
        // Find a salt that produces an address with the correct flags
        (address hookAddress, bytes32 salt) = HookMiner.find(
            CREATE2_FACTORY,
            flags,
            type(UniroidHook).creationCode,
            constructorArgs
        );
        
        // Log the results
        console.log("Mining completed!");
        console.log("Hook address:", hookAddress);
        console.log("Hook address last 2 bytes (hex):", toHexString(uint160(hookAddress) & 0xFFFF, 2));
        console.log("Mined salt:", vm.toString(salt));
        
        // Display instructions for using the salt
        console.log("------------------------");
        console.log("IMPORTANT: Copy this salt value and use it in the deployment script");
        console.log("Set the HOOK_SALT environment variable to this value before running DeployUniroidHook.s.sol");
        console.log("HOOK_SALT=", vm.toString(salt));
        console.log("------------------------");
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

// Usage: forge script script/MineHookAddress.s.sol
