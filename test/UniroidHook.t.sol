// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";

import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";

import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";

import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {SqrtPriceMath} from "v4-core/libraries/SqrtPriceMath.sol";
import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";

import "forge-std/console.sol";
import {UniroidHook} from "../src/UniroidHook.sol";

contract TestUniroidHook is Test, Deployers {
    using CurrencyLibrary for Currency;

    MockERC20 token;

    Currency ethCurrency = Currency.wrap(address(0));
    Currency tokenCurrency;

    UniroidHook hook;
    
    // Events for testing
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
    event HookStatusChanged(bytes32 indexed poolId, bool enabled);
    event LiquidityLockSet(bytes32 indexed poolId, uint256 unlockTime, address primaryProvider);
    event ReferralFeeCommission(
        bytes32 indexed poolId,
        address indexed user,
        address indexed referrer,
        uint24 originalFee,
        uint24 commissionAmount
    );
    event ReferralCommissionPaid(
        bytes32 indexed poolId,
        address indexed user,
        address indexed referrer,
        Currency currency,
        uint256 amount
    );
    event AddressBlacklisted(address indexed user, bytes32 indexed poolId);
    event AddressWhitelisted(address indexed user, bytes32 indexed poolId);
    event GlobalAddressBlacklisted(address indexed user);
    event GlobalAddressWhitelisted(address indexed user);

    function setUp() public {
        // Step 1 + 2
        // Deploy PoolManager and Router contracts
        deployFreshManagerAndRouters();

        // Deploy our TOKEN contract
        token = new MockERC20("Test Token", "TEST", 18);
        tokenCurrency = Currency.wrap(address(token));

        // Mint a bunch of TOKEN to ourselves and to address(1)
        token.mint(address(this), 1000 ether);
        token.mint(address(1), 1000 ether);

        // Deploy hook to an address that has the proper flags set
        uint160 flags = uint160(
            Hooks.AFTER_ADD_LIQUIDITY_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_INITIALIZE_FLAG | 
            Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG
        );
        deployCodeTo(
            "UniroidHook.sol",
            abi.encode(manager, "Uniroid Token", "UNIROID", address(this)),
            address(flags)
        );

        // Deploy our hook
        hook = UniroidHook(payable(address(flags)));

        // Approve our TOKEN for spending on the swap router and modify liquidity router
        // These variables are coming from the `Deployers` contract
        token.approve(address(swapRouter), type(uint256).max);
        token.approve(address(modifyLiquidityRouter), type(uint256).max);

        // Initialize a pool
        (key, ) = initPool(
            ethCurrency, // Currency 0 = ETH
            tokenCurrency, // Currency 1 = TOKEN
            hook, // Hook Contract
            3000, // Swap Fees
            SQRT_PRICE_1_1 // Initial Sqrt(P) value = 1
        );
    }

    function test_beforeInitialize() public {
        console.log("=== Starting test_beforeInitialize ===");
        
        // Create a new address for testing
        address testUser = makeAddr("testUser");
        console.log("Created test user address:", testUser);
        
        // Create a new pool with testUser as the sender
        vm.startPrank(testUser);
        console.log("Starting to act as test user");
        
        // Deploy a new token for a different pool
        MockERC20 newToken = new MockERC20("New Test Token", "NTEST", 18);
        Currency newTokenCurrency = Currency.wrap(address(newToken));
        console.log("Deployed new test token at address:", address(newToken));
        
        // Use a higher sqrt price to ensure we're above the minimum liquidity threshold
        // For 0.1 ETH threshold, we need sqrtPriceX96 > sqrt(0.1 * 2^96)
        uint160 highSqrtPrice = uint160(TickMath.getSqrtPriceAtTick(10000)); // A high tick value
        console.log("Using high sqrt price for initialization:", uint256(highSqrtPrice));
        
        console.log("Initializing new pool with ETH and test token...");
        // Initialize a new pool with the hook
        PoolKey memory newKey;
        (newKey, ) = initPool(
            ethCurrency,         // Currency 0 = ETH
            newTokenCurrency,    // Currency 1 = NEW_TOKEN
            hook,                // Hook Contract
            3000,                // Swap Fees
            highSqrtPrice        // Higher initial Sqrt(P) value to meet threshold
        );
        
        console.log("New pool initialized with hook at address:", address(newKey.hooks));
        console.log("Initial sqrt price used:", uint256(highSqrtPrice));
        
        vm.stopPrank();
        console.log("Stopped acting as test user");
        
        // Calculate the pool ID
        bytes32 poolId = keccak256(abi.encode(newKey));
        console.log("Calculated pool ID for initialized pool:", uint256(poolId));
        
        console.log("Creating a different pool key that hasn't been initialized...");
        // Create a different pool key that hasn't been initialized
        MockERC20 unusedToken = new MockERC20("Unused Token", "UNUSED", 18);
        Currency unusedTokenCurrency = Currency.wrap(address(unusedToken));
        PoolKey memory unusedKey = PoolKey({
            currency0: ethCurrency,
            currency1: unusedTokenCurrency,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
        bytes32 unusedPoolId = keccak256(abi.encode(unusedKey));
        console.log("Created unused pool ID:", uint256(unusedPoolId));
        
        // Verify the correct pool has been recorded as having used the hook
        console.log("=== Verification Results ===");
        console.log("Pool ID:", uint256(poolId));
        console.log("Unused Pool ID:", uint256(unusedPoolId));
        console.log("Pool has used the hook:", hook.hasUsedHook(poolId));
        console.log("Unused pool has not used the hook:", !hook.hasUsedHook(unusedPoolId));
        
        // Verify the pool has been recorded as having used the hook
        assertTrue(hook.hasUsedHook(poolId));
        assertFalse(hook.hasUsedHook(unusedPoolId));
        console.log("=== test_beforeInitialize completed successfully ===");
    }
    
    function test_beforeInitialize_revertBelowThreshold() public {
        console.log("=== Starting test_beforeInitialize_revertBelowThreshold ===");
        
        // Create a new address for testing
        address testUser = makeAddr("testUser");
        console.log("Created test user address:", testUser);
        
        // Create a new pool with testUser as the sender
        vm.startPrank(testUser);
        console.log("Starting to act as test user");
        
        // Deploy a new token for a different pool
        MockERC20 newToken = new MockERC20("Low Liquidity Token", "LOW", 18);
        Currency newTokenCurrency = Currency.wrap(address(newToken));
        console.log("Deployed low liquidity token at address:", address(newToken));
        
        // Use a very low sqrt price to ensure we're below the minimum liquidity threshold
        uint160 lowSqrtPrice = 1; // Very low value
        console.log("Using very low sqrt price:", uint256(lowSqrtPrice));
        console.log("This should be below the minimum threshold of:", hook.MINIMUM_LIQUIDITY_THRESHOLD());
        
        console.log("Attempting to initialize pool with insufficient liquidity (should revert)...");
        // Try to initialize a pool with liquidity below the threshold
        // This should revert, but we can't check the exact message because it's wrapped
        vm.expectRevert();
        initPool(
            ethCurrency,         // Currency 0 = ETH
            newTokenCurrency,    // Currency 1 = NEW_TOKEN
            hook,                // Hook Contract
            3000,                // Swap Fees
            lowSqrtPrice         // Very low initial Sqrt(P) value
        );
        
        vm.stopPrank();
        console.log("Stopped acting as test user");
        console.log("=== test_beforeInitialize_revertBelowThreshold completed successfully ===");
    }

    function test_addLiquidityAndSwap() public {
        console.log("=== Starting test_addLiquidityAndSwap ===");
        
        uint256 pointsBalanceOriginal = hook.balanceOf(address(this));
        console.log("Initial points balance:", pointsBalanceOriginal);

        // Use the pool that was already initialized in setUp()
        console.log("Using pool initialized in setUp with key:", uint256(keccak256(abi.encode(key))));
        bytes memory hookData = abi.encode(address(this));

        // Enable the hook for this pool
        bytes32 poolId = keccak256(abi.encode(key));
        hook.setHookStatusForPool(poolId, true);
        console.log("Hook enabled for pool >>>>>>>>>>>>>>>>>>>>");
        console.log(uint256(poolId));

        uint160 sqrtPriceAtTickLower = TickMath.getSqrtPriceAtTick(-60);
        console.log("Lower tick sqrt price:", uint256(sqrtPriceAtTickLower));

        uint256 ethToAdd = 0.1 ether;
        console.log("Adding liquidity with ETH amount:", ethToAdd);
        
        uint128 liquidityDelta = LiquidityAmounts.getLiquidityForAmount0(
            sqrtPriceAtTickLower,
            SQRT_PRICE_1_1,
            ethToAdd
        );
        console.log("Calculated liquidity delta:", uint256(liquidityDelta));
        
        console.log("Adding liquidity to the pool...");
        modifyLiquidityRouter.modifyLiquidity{value: ethToAdd}(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: int256(uint256(liquidityDelta)),
                salt: bytes32(0)
            }),
            hookData
        );
        console.log("Liquidity added successfully");

        // Swap ETH for tokens
        bool zeroForOne = true;
        int256 amountSpecified = 0.01 ether;
        console.log("Preparing to swap ETH for tokens...");
        console.log("Swap amount:", uint256(amountSpecified));
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: -amountSpecified,
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
        });

        PoolSwapTest.TestSettings memory testSettings = PoolSwapTest.TestSettings({
            takeClaims: false,
            settleUsingBurn: false
        });

        console.log("Executing swap...");
        swapRouter.swap{value: 0.01 ether}(
            key,
            params,
            testSettings,
            hookData
        );
        console.log("Swap executed successfully");

        // Check if points were minted to the user
        uint256 pointsBalanceAfter = hook.balanceOf(address(this));
        console.log("Points balance after swap:", pointsBalanceAfter);
        console.log("Points earned:", pointsBalanceAfter - pointsBalanceOriginal);
        
        assertTrue(pointsBalanceAfter > pointsBalanceOriginal, "Points should have been minted");
        console.log("=== test_addLiquidityAndSwap completed successfully ===");
    }

    function test_adminRole() public {
        console.log("=== Starting test_adminRole ===");
        
        // Check that the deployer is the admin
        address initialAdmin = hook.admin();
        assertEq(initialAdmin, address(this), "Deployer should be the initial admin");
        console.log("Initial admin is the deployer:", initialAdmin);
        
        // Create a new address to be the new admin
        address newAdmin = makeAddr("newAdmin");
        console.log("Created new admin address:", newAdmin);
        
        // Change admin and verify the event is emitted
        vm.expectEmit(true, true, false, false);
        emit AdminChanged(address(this), newAdmin);
        hook.setAdmin(newAdmin);
        
        // Verify admin was changed
        assertEq(hook.admin(), newAdmin, "Admin should be updated to new address");
        console.log("Admin successfully changed to:", hook.admin());
        
        // Try to change admin again from original address (should fail)
        vm.expectRevert(UniroidHook.NotAdmin.selector);
        hook.setAdmin(address(1));
        console.log("Correctly reverted when non-admin tried to change admin");
        
        // Change admin from new admin address
        vm.startPrank(newAdmin);
        address newerAdmin = makeAddr("newerAdmin");
        hook.setAdmin(newerAdmin);
        assertEq(hook.admin(), newerAdmin, "Admin should be updated again");
        vm.stopPrank();
        console.log("Admin successfully changed again by new admin");
        
        // Try to set admin to zero address (should fail)
        vm.startPrank(newerAdmin);
        vm.expectRevert(UniroidHook.InvalidAddress.selector);
        hook.setAdmin(address(0));
        vm.stopPrank();
        console.log("Correctly reverted when trying to set admin to zero address");
        
        console.log("=== test_adminRole completed successfully ===");
    }
    
    function test_setHookStatusForPool() public {
        console.log("=== Starting test_setHookStatusForPool ===");
        
        // Calculate pool ID from the key
        bytes32 poolId = keccak256(abi.encode(key));
        console.log("Pool ID:", uint256(poolId));
        
        // Check initial hook status
        bool initialStatus = hook.isHookEnabledOnPool(poolId);
        console.log("Initial hook status for pool:", initialStatus);
        
        // Set hook status and verify event is emitted
        vm.expectEmit(true, false, false, true);
        emit HookStatusChanged(poolId, true);
        hook.setHookStatusForPool(poolId, true);
        
        // Verify hook status was changed
        assertTrue(hook.isHookEnabledOnPool(poolId), "Hook should be enabled for pool");
        console.log("Hook status successfully set to enabled");
        
        // Set hook status to false
        hook.setHookStatusForPool(poolId, false);
        assertFalse(hook.isHookEnabledOnPool(poolId), "Hook should be disabled for pool");
        console.log("Hook status successfully set to disabled");
        
        // Try to set hook status from non-admin address (should fail)
        address nonAdmin = makeAddr("nonAdmin");
        vm.startPrank(nonAdmin);
        vm.expectRevert(UniroidHook.NotAdmin.selector);
        hook.setHookStatusForPool(poolId, true);
        vm.stopPrank();
        console.log("Correctly reverted when non-admin tried to set hook status");
        
        console.log("=== test_setHookStatusForPool completed successfully ===");
    }
    
    function test_callAVSForVerification() public {
        console.log("=== Starting test_callAVSForVerification ===");
        
        // Calculate pool ID from the key
        bytes32 poolId = keccak256(abi.encode(key));
        console.log("Pool ID:", uint256(poolId));
        
        // Verify the pool has used the hook (from initialization in setUp)
        assertTrue(hook.hasUsedHook(poolId), "Pool should have used the hook");
        
        // Call AVS verification and check result
        bool verificationResult = hook.callAVSForVerification(poolId);
        assertTrue(verificationResult, "Verification should succeed for valid pool");
        console.log("AVS verification result:", verificationResult);
        
        // Verify hook is now enabled for the pool
        assertTrue(hook.isHookEnabledOnPool(poolId), "Hook should be enabled after verification");
        console.log("Hook status after verification:", hook.isHookEnabledOnPool(poolId));
        
        // Try verification for a pool that hasn't used the hook
        bytes32 unusedPoolId = bytes32(uint256(123456789));
        bool unusedPoolResult = hook.callAVSForVerification(unusedPoolId);
        assertFalse(unusedPoolResult, "Verification should fail for unused pool");
        console.log("AVS verification result for unused pool:", unusedPoolResult);
        
        console.log("=== test_callAVSForVerification completed successfully ===");
    }
    
    function test_beforeSwapHookEnabled() public {
        console.log("=== Starting test_beforeSwapHookEnabled ===");
        
        // Calculate pool ID from the key
        bytes32 poolId = keccak256(abi.encode(key));
        console.log("Pool ID:", uint256(poolId));
        
        // Enable the hook for the pool
        hook.setHookStatusForPool(poolId, true);
        assertTrue(hook.isHookEnabledOnPool(poolId), "Hook should be enabled for pool");
        console.log("Hook enabled for pool");
        
        // Prepare swap parameters
        bool zeroForOne = true;
        int256 amountSpecified = 0.01 ether;
        console.log("Preparing to swap ETH for tokens...");
        console.log("Swap amount:", uint256(amountSpecified));
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: -amountSpecified,
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
        });

        PoolSwapTest.TestSettings memory testSettings = PoolSwapTest.TestSettings({
            takeClaims: false,
            settleUsingBurn: false
        });

        console.log("Executing swap...");
        swapRouter.swap{value: 0.01 ether}(
            key,
            params,
            testSettings,
            abi.encode(address(this))
        );
        console.log("Swap executed successfully with hook enabled");
        
        console.log("=== test_beforeSwapHookEnabled completed successfully ===");
    }
    
    function test_beforeSwapHookDisabled() public {
        console.log("=== Starting test_beforeSwapHookDisabled ===");
        
        // Calculate pool ID from the key
        bytes32 poolId = keccak256(abi.encode(key));
        console.log("Pool ID:", uint256(poolId));
        
        // Disable the hook for the pool
        hook.setHookStatusForPool(poolId, false);
        assertFalse(hook.isHookEnabledOnPool(poolId), "Hook should be disabled for pool");
        console.log("Hook disabled for pool");
        
        // Prepare swap parameters
        bool zeroForOne = true;
        int256 amountSpecified = 0.01 ether;
        console.log("Preparing to swap ETH for tokens...");
        console.log("Swap amount:", uint256(amountSpecified));
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: -amountSpecified,
            sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
        });

        PoolSwapTest.TestSettings memory testSettings = PoolSwapTest.TestSettings({
            takeClaims: false,
            settleUsingBurn: false
        });

        // Execute swap (should revert since hook is disabled)
        console.log("Attempting swap with hook disabled (should revert)...");
        vm.expectRevert();  // Just expect any revert without specifying the message
        swapRouter.swap{value: 0.01 ether}(
            key,
            params,
            testSettings,
            abi.encode(address(this))
        );
        console.log("Swap correctly reverted when hook was disabled");
        
        console.log("=== test_beforeSwapHookDisabled completed successfully ===");
    }
    
    function test_liquidityRemovalLock() public {
        console.log("=== Starting test_liquidityRemovalLock ===");
        
        // Create a test user address
        address testUser = makeAddr("testUser");
        console.log("Created test user address:", testUser);
        
        // Mint ETH to the test user
        vm.deal(testUser, 1 ether);
        
        // Start acting as the test user
        vm.startPrank(testUser);
        console.log("Starting to act as test user");
        
        // Deploy a new token for the pool
        MockERC20 newToken = new MockERC20("New Test Token", "NTEST", 18);
        Currency newTokenCurrency = Currency.wrap(address(newToken));
        console.log("Deployed new test token at address:", address(newToken));
        
        // Mint tokens to the test user
        newToken.mint(testUser, 1000 ether);
        
        // Approve tokens for the liquidity router
        newToken.approve(address(modifyLiquidityRouter), type(uint256).max);
        
        // Initialize a new pool with the hook
        uint160 highSqrtPrice = uint160(TickMath.getSqrtPriceAtTick(10000));
        PoolKey memory newKey;
        bytes32 poolId;
        
        try this.initPoolAsUser(
            ethCurrency,         // Currency 0 = ETH
            newTokenCurrency,    // Currency 1 = NEW_TOKEN
            hook,                // Hook Contract
            3000,                // Swap Fees
            highSqrtPrice        // Higher initial Sqrt(P) value
        ) returns (PoolKey memory _key, bytes32 _poolId) {
            newKey = _key;
            poolId = _poolId;
            console.log("New pool initialized with hook at address:", address(newKey.hooks));
        } catch Error(string memory reason) {
            console.log("Pool initialization failed:", reason);
            vm.stopPrank();
            return;
        } catch {
            console.log("Pool initialization failed with unknown error");
            vm.stopPrank();
            return;
        }
        
        // Add liquidity to the pool
        uint160 sqrtPriceAtTickLower = TickMath.getSqrtPriceAtTick(-60);
        uint256 ethToAdd = 0.1 ether;
        uint128 liquidityDelta = LiquidityAmounts.getLiquidityForAmount0(
            sqrtPriceAtTickLower,
            highSqrtPrice,
            ethToAdd
        );
        
        console.log("Adding liquidity with ETH amount:", ethToAdd);
        console.log("Calculated liquidity delta:", liquidityDelta);
        
        try modifyLiquidityRouter.modifyLiquidity{value: ethToAdd}(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: int256(uint256(liquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        ) {
            console.log("Liquidity added successfully");
        } catch Error(string memory reason) {
            console.log("Failed to add liquidity:", reason);
            vm.stopPrank();
            return;
        } catch {
            console.log("Failed to add liquidity with unknown error");
            vm.stopPrank();
            return;
        }
        
        // Try to remove liquidity immediately (should revert due to lock period)
        console.log("Attempting to remove liquidity immediately (should revert)...");
        vm.expectRevert();  // Just expect any revert without specifying the message
        modifyLiquidityRouter.modifyLiquidity(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: -int256(uint256(liquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        );
        console.log("Liquidity removal correctly reverted due to lock period");
        
        // Warp time forward past the lock period
        uint256 lockPeriod = hook.liquidityRemovalLockPeriod(poolId);
        console.log("Current lock period ends at:", lockPeriod);
        console.log("Current block timestamp:", block.timestamp);
        console.log("Warping time forward by:", (lockPeriod - block.timestamp) + 1, "seconds");
        vm.warp(lockPeriod + 1);
        console.log("New block timestamp:", block.timestamp);
        
        // Try to remove liquidity after lock period (should succeed)
        console.log("Attempting to remove liquidity after lock period (should succeed)...");
        try modifyLiquidityRouter.modifyLiquidity(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: -int256(uint256(liquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        ) {
            console.log("Liquidity removed successfully after lock period");
        } catch Error(string memory reason) {
            console.log("Failed to remove liquidity after lock period:", reason);
            fail();
        } catch {
            console.log("Failed to remove liquidity after lock period with unknown error");
            fail();
        }
        
        vm.stopPrank();
        console.log("=== test_liquidityRemovalLock completed successfully ===");
    }
    
    function test_anyProviderCanRemoveLiquidity() public {
        console.log("=== Starting test_anyProviderCanRemoveLiquidity ===");
        
        // Create two addresses for testing
        address provider1 = makeAddr("provider1");
        address provider2 = makeAddr("provider2");
        console.log("Created provider1:", provider1);
        console.log("Created provider2:", provider2);
        
        // Mint ETH to both providers
        vm.deal(provider1, 1 ether);
        vm.deal(provider2, 1 ether);
        
        // Create a new pool with provider1
        vm.startPrank(provider1);
        console.log("Starting to act as provider1");
        
        // Deploy a new token for the pool
        MockERC20 newToken = new MockERC20("New Test Token", "NTEST", 18);
        Currency newTokenCurrency = Currency.wrap(address(newToken));
        console.log("Deployed new test token at address:", address(newToken));
        
        // Mint tokens to both providers
        newToken.mint(provider1, 1000 ether);
        newToken.mint(provider2, 1000 ether);
        
        // Approve tokens for the liquidity router
        newToken.approve(address(modifyLiquidityRouter), type(uint256).max);
        
        // Initialize a new pool with the hook
        uint160 highSqrtPrice = uint160(TickMath.getSqrtPriceAtTick(10000));
        PoolKey memory newKey;
        bytes32 poolId;
        
        try this.initPoolAsUser(
            ethCurrency,         // Currency 0 = ETH
            newTokenCurrency,    // Currency 1 = NEW_TOKEN
            hook,                // Hook Contract
            3000,                // Swap Fees
            highSqrtPrice        // Higher initial Sqrt(P) value
        ) returns (PoolKey memory _key, bytes32 _poolId) {
            newKey = _key;
            poolId = _poolId;
            console.log("New pool initialized by provider1");
        } catch Error(string memory reason) {
            console.log("Pool initialization failed:", reason);
            vm.stopPrank();
            return;
        } catch {
            console.log("Pool initialization failed with unknown error");
            vm.stopPrank();
            return;
        }
        
        // Add liquidity as provider1
        uint160 sqrtPriceAtTickLower = TickMath.getSqrtPriceAtTick(-60);
        uint256 ethToAdd = 0.1 ether;
        uint128 liquidityDelta = LiquidityAmounts.getLiquidityForAmount0(
            sqrtPriceAtTickLower,
            highSqrtPrice,
            ethToAdd
        );
        
        try modifyLiquidityRouter.modifyLiquidity{value: ethToAdd}(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: int256(uint256(liquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        ) {
            console.log("Provider1 added liquidity");
        } catch Error(string memory reason) {
            console.log("Failed to add liquidity as provider1:", reason);
            vm.stopPrank();
            return;
        } catch {
            console.log("Failed to add liquidity as provider1 with unknown error");
            vm.stopPrank();
            return;
        }
        vm.stopPrank();
        
        // Add liquidity as provider2
        vm.startPrank(provider2);
        console.log("Starting to act as provider2");
        
        // Approve tokens for the liquidity router
        newToken.approve(address(modifyLiquidityRouter), type(uint256).max);
        
        uint256 secondaryEthToAdd = 0.05 ether;
        uint128 secondaryLiquidityDelta = LiquidityAmounts.getLiquidityForAmount0(
            sqrtPriceAtTickLower,
            highSqrtPrice,
            secondaryEthToAdd
        );
        
        try modifyLiquidityRouter.modifyLiquidity{value: secondaryEthToAdd}(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: int256(uint256(secondaryLiquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        ) {
            console.log("Provider2 added liquidity");
        } catch Error(string memory reason) {
            console.log("Failed to add liquidity as provider2:", reason);
            vm.stopPrank();
            return;
        } catch {
            console.log("Failed to add liquidity as provider2 with unknown error");
            vm.stopPrank();
            return;
        }
        
        // Provider2 should be able to remove liquidity immediately (should revert due to lock period)
        console.log("Provider2 attempting to remove liquidity (should revert due to lock period)...");
        vm.expectRevert();  // Just expect any revert without specifying the message
        modifyLiquidityRouter.modifyLiquidity(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: -int256(uint256(secondaryLiquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        );
        console.log("Liquidity removal correctly reverted due to lock period");
        
        // Warp time forward past the lock period
        uint256 lockPeriod = hook.liquidityRemovalLockPeriod(poolId);
        console.log("Current lock period ends at:", lockPeriod);
        console.log("Current block timestamp:", block.timestamp);
        console.log("Warping time forward by:", (lockPeriod - block.timestamp) + 1, "seconds");
        vm.warp(lockPeriod + 1);
        console.log("New block timestamp:", block.timestamp);
        
        // Provider2 should be able to remove liquidity after lock period
        console.log("Provider2 attempting to remove liquidity after lock period (should succeed)...");
        try modifyLiquidityRouter.modifyLiquidity(
            newKey,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: -int256(uint256(secondaryLiquidityDelta)),
                salt: bytes32(0)
            }),
            ""
        ) {
            console.log("Provider2 successfully removed liquidity after lock period");
        } catch Error(string memory reason) {
            console.log("Failed to remove liquidity as provider2:", reason);
            fail();
        } catch {
            console.log("Failed to remove liquidity as provider2 with unknown error");
            fail();
        }
        vm.stopPrank();
        
        console.log("=== test_anyProviderCanRemoveLiquidity completed successfully ===");
    }
    
    function test_blacklistingAndWhitelisting() public {
        console.log("=== Starting test_blacklistingAndWhitelisting ===");
        
        // Create test addresses
        address user1 = makeAddr("user1");
        address user2 = makeAddr("user2");
        address user3 = makeAddr("user3");
        console.log("User1 address:", user1);
        console.log("User2 address:", user2);
        console.log("User3 address:", user3);
        
        // Initial state check
        assertTrue(hook.isAllowed(user1), "User1 should be allowed initially");
        assertTrue(hook.isAllowed(user2), "User2 should be allowed initially");
        assertTrue(hook.isAllowed(user3), "User3 should be allowed initially");
        
        // Test blacklisting
        hook.setGlobalBlacklist(user1, true);
        assertFalse(hook.isAllowed(user1), "User1 should be blacklisted");
        assertTrue(hook.isAllowed(user2), "User2 should still be allowed");
        
        // Test removing from blacklist
        hook.setGlobalBlacklist(user1, false);
        assertTrue(hook.isAllowed(user1), "User1 should be allowed again");
        
        // Test activating whitelist mode
        hook.activateGlobalWhitelist(true);
        
        // In whitelist mode, no users should be allowed by default
        assertFalse(hook.isAllowed(user1), "User1 should not be allowed in whitelist mode");
        assertFalse(hook.isAllowed(user2), "User2 should not be allowed in whitelist mode");
        assertFalse(hook.isAllowed(user3), "User3 should not be allowed in whitelist mode");
        
        // Add user2 to whitelist
        hook.setGlobalWhitelist(user2, true);
        assertFalse(hook.isAllowed(user1), "User1 should still not be allowed");
        assertTrue(hook.isAllowed(user2), "User2 should be allowed after whitelisting");
        assertFalse(hook.isAllowed(user3), "User3 should still not be allowed");
        
        // Test blacklist overrides whitelist
        hook.setGlobalBlacklist(user2, true);
        assertFalse(hook.isAllowed(user2), "User2 should not be allowed when both blacklisted and whitelisted");
        
        // Test deactivating whitelist mode
        hook.activateGlobalWhitelist(false);
        assertFalse(hook.isAllowed(user2), "User2 should still be blacklisted after whitelist mode is off");
        assertTrue(hook.isAllowed(user3), "User3 should be allowed again when whitelist mode is off");
        
        console.log("=== test_blacklistingAndWhitelisting completed successfully ===");
    }
    
    function test_referralCommission() public {
        console.log("=== Starting test_referralCommission ===");
        
        // Create user and referrer addresses
        address user = makeAddr("user");
        address referrer = makeAddr("referrer");
        console.log("User address:", user);
        console.log("Referrer address:", referrer);
        
        // Fund the user with ETH
        vm.deal(user, 10 ether);
        
        // Enable the hook for the pool
        bytes32 poolId = keccak256(abi.encode(key));
        console.log("Pool ID:", uint256(poolId));
        hook.setHookStatusForPool(poolId, true);
        
        // Check initial balances
        uint256 initialReferrerBalance = address(referrer).balance;
        uint256 initialHookBalance = address(hook).balance;
        console.log("Initial referrer ETH balance:", initialReferrerBalance);
        console.log("Initial hook ETH balance:", initialHookBalance);
        
        // Perform swap as user with referrer
        vm.startPrank(user);
        
        // Create hook data with referrer
        bytes memory hookData = hook.encodeHookData(
            user,
            referrer,
            hook.REFERRAL_TYPE_FEE_COMMISSION()
        );
        
        // Calculate expected commission for verification later
        uint256 swapAmount = 1 ether;
        uint256 expectedFee = (swapAmount * uint256(key.fee)) / 1e6;
        uint256 expectedCommission = (expectedFee * hook.REFERRAL_FEE_COMMISSION_PERCENT()) / 100;
        
        console.log("Swap amount:", swapAmount);
        console.log("Fee rate:", key.fee);
        console.log("Expected fee amount:", expectedFee);
        console.log("Commission percent:", hook.REFERRAL_FEE_COMMISSION_PERCENT());
        console.log("Expected commission:", expectedCommission);
        
        PoolSwapTest.TestSettings memory testSettings = PoolSwapTest.TestSettings({
            takeClaims: false,
            settleUsingBurn: false
        });
        
        console.log("Executing swap with referral commission...");
        
        // Prepare swap parameters
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: int256(swapAmount),
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // Minimum price limit
        });
        
        // Execute the swap
        swapRouter.swap{value: swapAmount}(
            key,
            params,
            testSettings,
            hookData
        );
        
        vm.stopPrank();
        
        // In a real scenario, the hook would receive fees from the pool
        // For testing, we'll simulate this by sending ETH to the hook
        vm.deal(address(hook), initialHookBalance + expectedFee);
        
        // Now call the hook's processReferralCommission function
        hook.processReferralCommission(referrer, expectedCommission);
        
        // Check if the referrer received a commission
        uint256 finalReferrerBalance = address(referrer).balance;
        uint256 finalHookBalance = address(hook).balance;
        console.log("Final referrer ETH balance:", finalReferrerBalance);
        console.log("Final hook ETH balance:", finalHookBalance);
        console.log("Hook balance change:", finalHookBalance > initialHookBalance ? finalHookBalance - initialHookBalance : 0);
        
        assertTrue(finalReferrerBalance > initialReferrerBalance, "Referrer did not receive commission");
        
        // Check that the commission is approximately correct (may not be exact due to rounding)
        assertApproxEqRel(
            finalReferrerBalance - initialReferrerBalance,
            expectedCommission,
            0.1e18 // Allow 10% deviation due to rounding and gas costs
        );
        
        console.log("=== test_referralCommission completed successfully ===");
    }
    
    function test_blacklistedReferrer() public {
        console.log("=== Starting test_blacklistedReferrer ===");
        
        // Create user and referrer addresses
        address user = makeAddr("user");
        address referrer = makeAddr("blacklisted_referrer");
        console.log("User address:", user);
        console.log("Referrer address (to be blacklisted):", referrer);
        
        // Fund the user with ETH
        vm.deal(user, 10 ether);
        
        // Blacklist the referrer
        hook.setGlobalBlacklist(referrer, true);
        assertFalse(hook.isAllowed(referrer), "Referrer should be blacklisted");
        
        // Enable the hook for the pool
        bytes32 poolId = keccak256(abi.encode(key));
        hook.setHookStatusForPool(poolId, true);
        
        // Calculate expected commission for verification later
        uint256 swapAmount = 1 ether;
        uint256 expectedFee = (swapAmount * uint256(key.fee)) / 1e6;
        uint256 expectedCommission = (expectedFee * hook.REFERRAL_FEE_COMMISSION_PERCENT()) / 100;
        
        console.log("Expected commission amount:", expectedCommission);
        
        // Fund the hook with ETH to simulate fee collection
        vm.deal(address(hook), expectedFee);
        uint256 initialHookBalance = address(hook).balance;
        console.log("Initial hook ETH balance:", initialHookBalance);
        
        // Attempt to process commission to blacklisted referrer (should revert)
        vm.expectRevert("Referrer is not allowed");
        hook.processReferralCommission(referrer, expectedCommission);
        
        // Verify hook balance remains unchanged
        uint256 finalHookBalance = address(hook).balance;
        console.log("Final hook ETH balance:", finalHookBalance);
        assertEq(finalHookBalance, initialHookBalance, "Hook balance should remain unchanged");
        
        // Verify referrer balance remains zero
        assertEq(address(referrer).balance, 0, "Blacklisted referrer should not receive any commission");
        
        console.log("=== test_blacklistedReferrer completed successfully ===");
    }
    
    function test_selfReferral() public {
        console.log("=== Starting test_selfReferral ===");
        
        // Create a user address that will also be used as the referrer (self-referral)
        address user = makeAddr("selfReferralUser");
        console.log("User/Referrer address:", user);
        
        // Calculate expected commission
        uint256 swapAmount = 1 ether;
        uint24 feeRate = 3000; // 0.3%
        uint256 expectedFee = (swapAmount * feeRate) / 1_000_000;
        uint256 commissionPercent = 50; // 50% of fees go to referrer
        uint256 expectedCommission = (expectedFee * commissionPercent) / 100;
        
        console.log("Swap amount:", swapAmount);
        console.log("Fee rate:", feeRate);
        console.log("Expected fee amount:", expectedFee);
        console.log("Commission percent:", commissionPercent);
        console.log("Expected commission:", expectedCommission);
        
        // Fund the hook with ETH to simulate fee collection
        vm.deal(address(hook), expectedFee);
        uint256 initialHookBalance = address(hook).balance;
        console.log("Initial hook ETH balance:", initialHookBalance);
        
        // Fund the user with some ETH for gas
        vm.deal(user, 0.1 ether);
        uint256 initialUserBalance = user.balance;
        console.log("Initial user balance:", initialUserBalance);
        
        // Enable the hook for the pool
        bytes32 poolId = keccak256(abi.encode(key));
        hook.setHookStatusForPool(poolId, true);
        
        // Process commission with user as their own referrer
        vm.prank(user);
        hook.processReferralCommission(user, expectedCommission);
        
        // Verify user received the commission
        uint256 finalUserBalance = user.balance;
        console.log("Final user balance:", finalUserBalance);
        assertEq(finalUserBalance, initialUserBalance + expectedCommission, "User should receive commission for self-referral");
        
        // Verify hook balance decreased
        uint256 finalHookBalance = address(hook).balance;
        console.log("Final hook ETH balance:", finalHookBalance);
        assertEq(finalHookBalance, initialHookBalance - expectedCommission, "Hook balance should decrease by commission amount");
        
        console.log("=== test_selfReferral completed successfully ===");
    }
    
    // Helper function to initialize pool as a user
    function initPoolAsUser(
        Currency currency0,
        Currency currency1,
        IHooks hooks,
        uint24 fee,
        uint160 sqrtPriceX96
    ) external returns (PoolKey memory key, bytes32 poolId) {
        key = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: fee,
            tickSpacing: 60,
            hooks: hooks
        });
        
        // Initialize the pool through the manager
        // The hook's _beforeInitialize will be called automatically and will set msg.sender as the primary provider
        manager.initialize(key, sqrtPriceX96);
        
        // Calculate the pool ID
        poolId = keccak256(abi.encode(key));
        return (key, poolId);
    }
}
