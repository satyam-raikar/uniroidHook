// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";

import {Currency} from "v4-core/types/Currency.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta} from "v4-core/types/BeforeSwapDelta.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";

import {Hooks} from "v4-core/libraries/Hooks.sol";

contract UniroidHook is BaseHook, ERC20 {
    // Hook data keys
    uint8 private constant KEY_USER_ADDRESS = 1;
    uint8 private constant KEY_REFERRER_ADDRESS = 2;
    uint8 private constant KEY_REFERRAL_TYPE = 3;
    uint8 private constant KEY_CUSTOM_DATA = 4;
    // Add more keys as needed in the future

    // Referral types
    uint8 private constant REFERRAL_TYPE_NONE = 0;
    uint8 private constant REFERRAL_TYPE_FEE_COMMISSION = 1;
    
    // Referral fee commission percentage (50%)
    uint8 private constant REFERRAL_FEE_COMMISSION_PERCENT = 50;

    // Mapping to track pools that have used the hook
    mapping(bytes32 => bool) public hasUsedHook;

    // Mapping to track if hook is enabled on a specific pool
    mapping(bytes32 => bool) public isHookEnabledOnPool;

    // Mapping to track liquidity removal lock period for each pool (in Unix timestamp)
    mapping(bytes32 => uint256) public liquidityRemovalLockPeriod;

    // Mapping to track premium subscribers and their subscription expiration timestamp
    mapping(address => uint256) public isPremiumSubscriber;

    // Mapping to track original swap fees for pools (used to restore fees after premium user swaps)
    mapping(bytes32 => uint24) public originalPoolFees;

    // Lock period duration in seconds (7 days)
    uint256 private constant LOCK_PERIOD_DURATION = 7 days;

    // Minimum liquidity threshold required for initialization (0.1 ETH)
    uint256 private constant MINIMUM_LIQUIDITY_THRESHOLD = 0.1 ether;

    // Premium subscription price (1 ETH)
    uint256 private constant PREMIUM_SUBSCRIPTION_PRICE = 1 ether;

    // Premium subscription duration (1 year)
    uint256 private constant PREMIUM_SUBSCRIPTION_DURATION = 365 days;

    // Premium user fee discount percentage (50%)
    uint8 private constant PREMIUM_FEE_DISCOUNT_PERCENT = 50;

    // Admin address that can manage hook settings
    address public admin;

    // Blacklisting and whitelisting
    mapping(address => bool) public globalBlacklist;
    mapping(address => bool) public globalWhitelist;
    bool public globalWhitelistActive;
    
    // Events for blacklisting and whitelisting
    event GlobalAddressBlacklisted(address indexed user);
    event GlobalAddressWhitelisted(address indexed user);
    event GlobalWhitelistActivated(bool active);

    // Struct to store referral commission information
    struct ReferralCommission {
        address referrer;
        uint8 commissionPercent;
        bool processed;
    }
    
    // Mapping to track pending referral commissions
    // poolId => user => ReferralCommission
    mapping(bytes32 => mapping(address => ReferralCommission)) public pendingReferralCommissions;

    // Events
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
    event HookStatusChanged(bytes32 indexed poolId, bool enabled);
    event LiquidityLockSet(bytes32 indexed poolId, uint256 unlockTime);
    event PremiumSubscriptionPurchased(
        address indexed subscriber,
        uint256 expirationTime
    );
    event FeeDiscountApplied(
        bytes32 indexed poolId,
        address indexed user,
        uint24 originalFee,
        uint24 discountedFee
    );
    event ReferralFeeCommission(
        bytes32 indexed poolId,
        address indexed user,
        address indexed referrer,
        uint24 commissionAmount
    );
    event ReferralCommissionPaid(address indexed referrer, uint256 amount);
    event ReferralCommissionFailed(address indexed referrer, uint256 amount);
    event ReferralCommissionCalculated(address indexed referrer, uint256 amount, bool zeroForOne, int256 deltaAmount0, int256 deltaAmount1);
    event FeeRestored(bytes32 indexed poolId, uint24 restoredFee);
    event TokensMinted(address indexed recipient, uint256 amount);

    // Errors
    error NotAdmin();
    error InvalidAddress();
    error NoVestingOrTokenLock();
    error MaliciousCodeDetected();
    error AVSVerificationFailed();
    error LiquidityLockPeriodNotExpired(uint256 unlockTime);
    error InsufficientPayment();

    constructor(
        IPoolManager _manager,
        string memory _name,
        string memory _symbol,
        address _admin
    ) BaseHook(_manager) ERC20(_name, _symbol, 18) {
        admin = _admin; // Set deployer as initial admin
    }

    /**
     * @notice Modifier to restrict function access to admin only
     */
    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    /**
     * @notice Modifier to check if the caller is a premium subscriber
     */
    modifier onlyPremiumSubscriber() {
        require(
            isPremiumSubscriber[msg.sender] > block.timestamp,
            "Not a premium subscriber or subscription expired"
        );
        _;
    }

    /**
     * @notice Checks if an address is allowed to interact with the contract
     * @dev Reverts if the address is blacklisted or not whitelisted when whitelist is active
     * @param user The address to check
     * @param poolId The pool ID to check pool-specific lists
     */
    modifier checkAllowed(address user, bytes32 poolId) {
        // Skip checks for zero address
        if (user == address(0)) {
            _;
            return;
        }

        // Check global blacklist
        if (globalBlacklist[user]) {
            revert("UniroidHook: Address is globally blacklisted");
        }

        // Check global whitelist if active
        if (globalWhitelistActive && !globalWhitelist[user]) {
            revert("UniroidHook: Address is not in global whitelist");
        }

        _;
    }

    /**
     * @notice Checks if an address is allowed to interact with the contract without reverting
     * @dev Returns false if the address is blacklisted or not whitelisted when whitelist is active
     * @param user The address to check
     * @return allowed True if the address is allowed, false otherwise
     */
    function isAllowed(
        address user
    ) public view returns (bool allowed) {
        // Check global blacklist
        if (globalBlacklist[user]) {
            return false;
        }

        // Check global whitelist if active
        if (globalWhitelistActive && !globalWhitelist[user]) {
            return false;
        }

        return true;
    }

    /**
     * @notice Changes the admin address
     * @param newAdmin The address of the new admin
     */
    function setAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert InvalidAddress();

        address oldAdmin = admin;
        admin = newAdmin;

        emit AdminChanged(oldAdmin, newAdmin);
    }

    /**
     * @notice Allows admin to set the hook status for a specific pool
     * @param poolId The unique identifier for the pool
     * @param enabled Whether the hook should be enabled for the pool
     */
    function setHookStatusForPool(
        bytes32 poolId,
        bool enabled
    ) external onlyAdmin {
        isHookEnabledOnPool[poolId] = enabled;

        emit HookStatusChanged(poolId, enabled);
    }

    /**
     * @notice Calls AVS for off-chain verification and updates the hook status for a pool
     * @param poolId The unique identifier for the pool
     * @return status Boolean indicating whether the hook is now enabled for the pool
     */
    function callAVSForVerification(bytes32 poolId) external returns (bool) {
        // This function will integrate with EigenLayer AVS service for off-chain verification
        // The actual implementation will be added later

        // Check if the pool has used the hook first
        if (!hasUsedHook[poolId]) {
            return false;
        }

        // --- Off-chain verification checks ---
        // These checks will be performed by EigenLayer AVS service
        // For now, we'll add placeholders with comments

        // 1. Check if there is a valid vesting done or tokens locked for the project
        bool hasValidVestingOrTokenLock = _checkVestingOrTokenLock(poolId);
        if (!hasValidVestingOrTokenLock) {
            revert NoVestingOrTokenLock();
        }

        // 2. Check with AI models if the contract has malicious code patterns
        bool isMaliciousCodeDetected = _checkForMaliciousCode(poolId);
        if (isMaliciousCodeDetected) {
            revert MaliciousCodeDetected();
        }

        // If all checks pass, enable the hook for this pool
        isHookEnabledOnPool[poolId] = true;
        emit HookStatusChanged(poolId, true);

        return true;
    }

    /**
     * @notice Placeholder function for checking vesting or token lock status
     * @dev Will be replaced with actual EigenLayer AVS integration
     * @return result Boolean indicating if the pool has valid vesting or token lock
     */
    function _checkVestingOrTokenLock(
        bytes32 /* poolId */
    ) internal pure returns (bool) {
        // Placeholder - will be implemented with EigenLayer AVS integration
        // This will verify if there is a valid vesting done or tokens locked for the project

        // For now, return true to allow testing
        return true;
    }

    /**
     * @notice Placeholder function for checking malicious code patterns
     * @dev Will be replaced with actual EigenLayer AVS integration with AI models
     * @return result Boolean indicating if malicious code was detected (true = malicious)
     */
    function _checkForMaliciousCode(
        bytes32 /* poolId */
    ) internal pure returns (bool) {
        // Placeholder - will be implemented with EigenLayer AVS integration
        // This will use AI models to check for malicious code patterns, honeypots, etc.

        // For now, return false (no malicious code) to allow testing
        return false;
    }

    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
                beforeInitialize: true,
                afterInitialize: false,
                beforeAddLiquidity: false,
                beforeRemoveLiquidity: true,
                afterAddLiquidity: true,
                afterRemoveLiquidity: false,
                beforeSwap: true,
                afterSwap: true,
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnDelta: false,
                afterSwapReturnDelta: false,
                afterAddLiquidityReturnDelta: false,
                afterRemoveLiquidityReturnDelta: false
            });
    }

    function _beforeInitialize(
        address /* sender */,
        PoolKey calldata key,
        uint160 sqrtPriceX96
    ) internal override onlyPoolManager returns (bytes4) {
        // Only allow pools between a Token and ETH (where ETH is currency0)
        if (!key.currency0.isAddressZero()) {
            revert("Only ETH-Token pairs are allowed");
        }

        // Calculate the initial liquidity value in ETH
        // For a pool at 1:1 price, we can estimate the ETH value from the sqrtPriceX96
        // This is a simplified calculation and may need to be adjusted based on your needs
        uint256 initialLiquidity = (uint256(sqrtPriceX96) *
            uint256(sqrtPriceX96)) / (1 << 96);

        // Check if the initial liquidity is above the threshold
        if (initialLiquidity < MINIMUM_LIQUIDITY_THRESHOLD) {
            revert("Initial liquidity below minimum threshold");
        }

        // Record that this pool has used the hook
        // Use the hash of the pool key as a unique identifier for the pool
        bytes32 poolId = keccak256(abi.encode(key));
        hasUsedHook[poolId] = true;

        // Set the liquidity removal lock period for this pool
        uint256 unlockTime = block.timestamp + LOCK_PERIOD_DURATION;
        liquidityRemovalLockPeriod[poolId] = unlockTime;

        // Emit event for the lock period
        emit LiquidityLockSet(poolId, unlockTime);

        return this.beforeInitialize.selector;
    }

    function _beforeSwap(
        address /* sender */,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        bytes calldata hookData
    )
        internal
        override
        onlyPoolManager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // If this is not an ETH-TOKEN pool with this hook attached, ignore
        if (!key.currency0.isAddressZero())
            return (this.beforeSwap.selector, BeforeSwapDelta.wrap(0), 0);

        // Generate the pool ID from the key
        bytes32 poolId = keccak256(abi.encode(key));

        // Check if the hook is enabled for this pool
        if (!isHookEnabledOnPool[poolId]) {
            revert("UniroidHook: Hook not enabled for this pool");
        }

        // Default: no fee change
        uint24 dynamicFee = 0;

        // Try to get the user address from hookData
        if (hookData.length > 0) {
            (address user, address referrer, uint8 referralType) = _decodeHookData(hookData);

            // Check if user and referrer are allowed
            if (user != address(0) && !isAllowed(user)) {
                revert("UniroidHook: User is not allowed");
            }

            if (
                referrer != address(0) &&
                !isAllowed(referrer)
            ) {
                revert("UniroidHook: Referrer is not allowed");
            }

            // Handle fee-based commission referral
            if (
                referrer != address(0) &&
                referrer != user &&
                referralType == REFERRAL_TYPE_FEE_COMMISSION
            ) {
                // Store the original fee for this pool if not already stored
                if (originalPoolFees[poolId] == 0) {
                    originalPoolFees[poolId] = key.fee;
                }
                
                // Calculate the referrer's commission (50% of the fee)
                uint24 referrerCommission = uint24(
                    (uint256(key.fee) * REFERRAL_FEE_COMMISSION_PERCENT) / 100
                );
                
                // Calculate the remaining fee for the pool (50% of the original fee)
                uint24 remainingFee = uint24(
                    (uint256(key.fee) * (100 - REFERRAL_FEE_COMMISSION_PERCENT)) / 100
                );
                
                // Apply the reduced fee
                dynamicFee = remainingFee;
                
                // Store the referrer address and commission percentage for this swap
                // We'll use this in the afterSwap hook to distribute the commission
                pendingReferralCommissions[poolId][user] = ReferralCommission({
                    referrer: referrer,
                    commissionPercent: REFERRAL_FEE_COMMISSION_PERCENT,
                    processed: false
                });
                
                // Emit event for fee commission
                emit ReferralFeeCommission(poolId, user, referrer, referrerCommission);
                
                return (this.beforeSwap.selector, BeforeSwapDelta.wrap(0), dynamicFee);
            }

            // Check if the user is a premium subscriber
            if (
                user != address(0) &&
                isPremiumSubscriber[user] > block.timestamp
            ) {
                // Store the original fee for this pool if not already stored
                if (originalPoolFees[poolId] == 0) {
                    originalPoolFees[poolId] = key.fee;
                }

                // Calculate the discounted fee (e.g., 50% discount)
                uint24 discountedFee = uint24(
                    (uint256(key.fee) * (100 - PREMIUM_FEE_DISCOUNT_PERCENT)) /
                        100
                );

                // Apply the fee discount
                dynamicFee = discountedFee;

                // Now we can emit events since we're not in a view function
                emit FeeDiscountApplied(poolId, user, key.fee, discountedFee);
            }
        }

        return (this.beforeSwap.selector, BeforeSwapDelta.wrap(0), dynamicFee);
    }

    /**
     * @notice Helper function to process referral commission
     * @param referrer The referrer address
     * @param commissionAmount The amount of commission to pay
     */
    function _processCommission(
        address referrer,
        uint256 commissionAmount
    ) internal {
        // Only process if there's a commission to pay and the referrer is valid
        if (commissionAmount > 0 && referrer != address(0)) {
            // For testing purposes, we'll use a direct transfer
            // In production, we would need to handle this differently
            // by collecting fees and distributing them periodically
            (bool success, ) = payable(referrer).call{value: commissionAmount}("");
            require(success, "ETH transfer failed");
            
            emit ReferralCommissionPaid(referrer, commissionAmount);
        }
    }

    function _afterSwap(
        address /* sender */,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata swapParams,
        BalanceDelta delta,
        bytes calldata hookData
    ) internal override onlyPoolManager returns (bytes4, int128) {
        // Process referral commission if any
        if (hookData.length > 0) {
            (address user, address referrer, uint8 referralType) = _decodeHookData(hookData);
            
            // Skip if user is a premium subscriber
            if (isPremiumSubscriber[user] > block.timestamp) {
                // We still mint points even for premium users
                if (!swapParams.zeroForOne) {
                    // Mint points equal to 20% of the amount of ETH they spent
                    uint256 ethSpendAmount = uint256(int256(-delta.amount0()));
                    uint256 pointsForSwap = ethSpendAmount / 5;
                    
                    // Mint the points
                    _mintPoints(hookData, pointsForSwap);
                }
                
                return (this.afterSwap.selector, 0);
            }
            
            // Process referral commission
            if (
                referrer != address(0) && 
                referrer != user &&
                referralType == REFERRAL_TYPE_FEE_COMMISSION &&
                isAllowed(referrer)
            ) {
                // Calculate the commission amount based on the actual swap
                uint256 commissionAmount = 0;
                
                if (swapParams.zeroForOne && delta.amount0() < 0) {
                    // ETH was spent in the swap (amount0 is negative)
                    uint256 swapEthAmount = uint256(int256(-delta.amount0()));
                    uint256 swapFeeAmount = (swapEthAmount * uint256(key.fee)) / 1e6;
                    commissionAmount = (swapFeeAmount * REFERRAL_FEE_COMMISSION_PERCENT) / 100;
                } else if (!swapParams.zeroForOne && delta.amount1() < 0) {
                    // Token was spent in the swap (amount1 is negative)
                    uint256 tokenAmount = uint256(int256(-delta.amount1()));
                    uint256 tokenFeeAmount = (tokenAmount * uint256(key.fee)) / 1e6;
                    commissionAmount = (tokenFeeAmount * REFERRAL_FEE_COMMISSION_PERCENT) / 100;
                }
                
                // Emit debug event for commission calculation
                emit ReferralCommissionCalculated(referrer, commissionAmount, swapParams.zeroForOne, delta.amount0(), delta.amount1());
                
                // Process the commission if amount is greater than zero
                if (commissionAmount > 0) {
                    // For testing purposes, we'll transfer ETH directly to the referrer
                    // In a production environment, we would handle this differently
                    // This assumes the hook has received ETH from the swap fee
                    (bool success, ) = payable(referrer).call{value: commissionAmount}("");
                    if (success) {
                        emit ReferralCommissionPaid(referrer, commissionAmount);
                    } else {
                        emit ReferralCommissionFailed(referrer, commissionAmount);
                    }
                }
            }
        }
        
        // We only mint points if user is buying TOKEN with ETH
        if (!swapParams.zeroForOne) {
            // Mint points equal to 20% of the amount of ETH they spent
            uint256 ethSpendAmount = uint256(int256(-delta.amount0()));
            uint256 pointsForSwap = ethSpendAmount / 5;
            
            // Mint the points
            _mintPoints(hookData, pointsForSwap);
        }
        
        return (this.afterSwap.selector, 0);
    }

    function _afterAddLiquidity(
        address /* sender */,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata,
        BalanceDelta delta,
        BalanceDelta,
        bytes calldata hookData
    ) internal override onlyPoolManager returns (bytes4, BalanceDelta) {
        // If this is not an ETH-TOKEN pool with this hook attached, ignore
        if (!key.currency0.isAddressZero())
            return (this.afterSwap.selector, delta);

        // Mint points equivalent to how much ETH they're adding in liquidity
        uint256 pointsForAddingLiquidity = uint256(int256(-delta.amount0()));

        // Mint the points including any referral points
        _mintPoints(hookData, pointsForAddingLiquidity);

        return (this.afterAddLiquidity.selector, delta);
    }

    /**
     * @notice Mint points to a user for using the protocol
     * @param hookData The encoded hook data containing user information
     * @param points The number of points to mint
     */
    function _mintPoints(
        bytes calldata hookData,
        uint256 points
    ) internal {
        if (hookData.length == 0) return;

        (address user, address referrer, ) = _decodeHookData(hookData);

        // Check if user is allowed
        if (user == address(0) || !isAllowed(user)) return;

        // Mint points to user
        _mint(user, points);

        // Check if referrer is valid and mint referral points
        if (
            referrer != address(0) &&
            referrer != user &&
            isAllowed(referrer)
        ) {
            // Mint referral points (10% of user's points)
            _mint(referrer, points / 10);
        }
    }

    /**
     * @notice Decodes the hook data to extract user and referrer addresses
     * @param hookData The encoded hook data
     * @return user The user address
     * @return referrer The referrer address (if any)
     * @return referralType The type of referral (0 = none, 1 = fee commission)
     */
    function _decodeHookData(
        bytes calldata hookData
    ) internal pure returns (address user, address referrer, uint8 referralType) {
        // Default values
        user = address(0);
        referrer = address(0);
        referralType = REFERRAL_TYPE_NONE;

        // Try to decode using the new format (TLV)
        if (hookData.length > 0) {
            uint256 i = 0;
            while (i < hookData.length) {
                // Ensure there's enough data for key and length
                if (i + 2 > hookData.length) break;

                // Read key and data length
                uint8 key = uint8(hookData[i]);
                uint8 dataLength = uint8(hookData[i + 1]);

                // Ensure there's enough data for the value
                if (i + 2 + dataLength > hookData.length) break;

                // Process based on key
                if (key == KEY_USER_ADDRESS && dataLength == 20) {
                    // Extract user address (20 bytes)
                    user = _bytesToAddress(hookData[i + 2:i + 2 + dataLength]);
                } else if (key == KEY_REFERRER_ADDRESS && dataLength == 20) {
                    // Extract referrer address (20 bytes)
                    referrer = _bytesToAddress(
                        hookData[i + 2:i + 2 + dataLength]
                    );
                } else if (key == KEY_REFERRAL_TYPE && dataLength == 1) {
                    // Extract referral type (1 byte)
                    referralType = uint8(hookData[i + 2]);
                }
                // Skip other keys for now

                // Move to next key-value pair
                i += 2 + dataLength;
            }
        }

        // Fallback to old format if user is still zero
        if (user == address(0) && hookData.length == 32) {
            // Try to decode as the old format (just a user address)
            user = abi.decode(hookData, (address));
        }
    }

    /**
     * @notice Converts bytes to an address
     * @param data The bytes to convert
     * @return addr The resulting address
     */
    function _bytesToAddress(
        bytes calldata data
    ) internal pure returns (address addr) {
        require(data.length == 20, "Invalid address length");
        assembly {
            addr := calldataload(data.offset)
        }
    }

    /**
     * @notice Encodes hook data with user and optional referrer
     * @param user The user address
     * @param referrer The referrer address (optional)
     * @param referralType The type of referral (0 = none, 1 = fee commission)
     * @return The encoded hook data
     */
    function encodeHookData(
        address user,
        address referrer,
        uint8 referralType
    ) external pure returns (bytes memory) {
        // Calculate the total length needed
        uint256 totalLength = 0;

        // User address (key + length + address = 2 + 20 = 22 bytes)
        totalLength += 22;

        // Referrer address if provided (key + length + address = 2 + 20 = 22 bytes)
        if (referrer != address(0)) {
            totalLength += 22;
            
            // Referral type (key + length + type = 2 + 1 = 3 bytes)
            totalLength += 3;
        }

        // Create the result array
        bytes memory result = new bytes(totalLength);
        uint256 position = 0;

        // Add user address
        result[position++] = bytes1(KEY_USER_ADDRESS);
        result[position++] = bytes1(uint8(20)); // Address length is 20 bytes
        for (uint256 i = 0; i < 20; i++) {
            result[position++] = bytes1(uint8(uint160(user) >> (8 * (19 - i))));
        }

        // Add referrer if provided
        if (referrer != address(0)) {
            result[position++] = bytes1(KEY_REFERRER_ADDRESS);
            result[position++] = bytes1(uint8(20)); // Address length is 20 bytes
            for (uint256 i = 0; i < 20; i++) {
                result[position++] = bytes1(
                    uint8(uint160(referrer) >> (8 * (19 - i)))
                );
            }
            
            // Add referral type
            result[position++] = bytes1(KEY_REFERRAL_TYPE);
            result[position++] = bytes1(uint8(1)); // Type length is 1 byte
            result[position++] = bytes1(referralType);
        }

        return result;
    }

    /**
     * @notice Encodes hook data with custom data
     * @param user The user address
     * @param customData The custom data to include
     * @return The encoded hook data
     */
    function encodeHookDataWithCustom(
        address user,
        bytes calldata customData
    ) external pure returns (bytes memory) {
        // Calculate the total length needed
        uint256 totalLength = 0;

        // User address (key + length + address = 2 + 20 = 22 bytes)
        totalLength += 22;

        // Custom data (key + length + data = 2 + customData.length)
        if (customData.length > 0) {
            totalLength += 2 + customData.length;
        }

        // Create the result array
        bytes memory result = new bytes(totalLength);
        uint256 position = 0;

        // Add user address
        result[position++] = bytes1(KEY_USER_ADDRESS);
        result[position++] = bytes1(uint8(20)); // Address length is 20 bytes
        for (uint256 i = 0; i < 20; i++) {
            result[position++] = bytes1(uint8(uint160(user) >> (8 * (19 - i))));
        }

        // Add custom data if provided
        if (customData.length > 0) {
            result[position++] = bytes1(KEY_CUSTOM_DATA);
            result[position++] = bytes1(uint8(customData.length)); // Length of custom data
            for (uint256 i = 0; i < customData.length; i++) {
                result[position++] = customData[i];
            }
        }

        return result;
    }

    /**
     * @notice Purchase a premium subscription for 1 ETH with 1 year duration
     * @dev Allows users to buy a premium subscription that lasts for 1 year
     */
    function buyPremiumSubscription() external payable {
        // Ensure payment is exactly 1 ETH
        if (msg.value != PREMIUM_SUBSCRIPTION_PRICE) {
            revert InsufficientPayment();
        }

        // Calculate expiration time (current time + 1 year)
        uint256 expirationTime = block.timestamp +
            PREMIUM_SUBSCRIPTION_DURATION;

        // If user already has a subscription, extend it
        if (isPremiumSubscriber[msg.sender] > block.timestamp) {
            expirationTime =
                isPremiumSubscriber[msg.sender] +
                PREMIUM_SUBSCRIPTION_DURATION;
        }

        // Update the subscription status
        isPremiumSubscriber[msg.sender] = expirationTime;

        // Emit event
        emit PremiumSubscriptionPurchased(msg.sender, expirationTime);
    }

    /**
     * @notice Check if an address is a premium subscriber
     * @param user The address to check
     * @return isActive Whether the user has an active premium subscription
     * @return expirationTime The timestamp when the subscription expires (0 if not active)
     */
    function checkPremiumSubscription(
        address user
    ) external view returns (bool isActive, uint256 expirationTime) {
        expirationTime = isPremiumSubscriber[user];
        isActive = expirationTime > block.timestamp;
        return (isActive, expirationTime);
    }

    /**
     * @notice Allows admin to withdraw ETH from the contract
     * @param recipient The address to send ETH to
     * @param amount The amount of ETH to withdraw
     */
    function withdrawETH(
        address payable recipient,
        uint256 amount
    ) external onlyAdmin {
        require(recipient != address(0), "Invalid recipient");
        require(address(this).balance >= amount, "Insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    // Admin functions for blacklisting/whitelisting
    function setGlobalBlacklist(
        address user,
        bool blacklisted
    ) external onlyAdmin {
        globalBlacklist[user] = blacklisted;
        emit GlobalAddressBlacklisted(user);
    }

    function setGlobalWhitelist(
        address user,
        bool whitelisted
    ) external onlyAdmin {
        globalWhitelist[user] = whitelisted;
        emit GlobalAddressWhitelisted(user);
    }

    function activateGlobalWhitelist(bool active) external onlyAdmin {
        globalWhitelistActive = active;
        emit GlobalWhitelistActivated(active);
    }

    /**
     * @notice Allows admin to mint tokens to any address
     * @param recipient The address to receive the tokens
     * @param amount The amount of tokens to mint
     */
    function mint(
        address recipient,
        uint256 amount
    ) external onlyAdmin {
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Amount must be greater than 0");
        
        // Mint tokens to the recipient
        _mint(recipient, amount);
        
        emit TokensMinted(recipient, amount);
    }
    
    /**
     * @notice Allows admin to batch mint tokens to multiple addresses
     * @param recipients Array of addresses to receive tokens
     * @param amounts Array of token amounts to mint
     */
    function batchMint(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external onlyAdmin {
        require(recipients.length == amounts.length, "Array lengths must match");
        require(recipients.length > 0, "Empty arrays");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            require(amounts[i] > 0, "Amount must be greater than 0");
            
            // Mint tokens to each recipient
            _mint(recipients[i], amounts[i]);
            
            emit TokensMinted(recipients[i], amounts[i]);
        }
    }

    /**
     * @notice Process referral commission for testing purposes
     * @param referrer The referrer address
     * @param commissionAmount The amount of commission to pay
     */
    function processReferralCommission(address referrer, uint256 commissionAmount) external {
        require(commissionAmount > 0, "Commission amount must be greater than 0");
        require(referrer != address(0), "Referrer cannot be zero address");
        require(isAllowed(referrer), "Referrer is not allowed");
        
        // Transfer ETH to the referrer
        (bool success, ) = payable(referrer).call{value: commissionAmount}("");
        require(success, "ETH transfer failed");
        
        emit ReferralCommissionPaid(referrer, commissionAmount);
    }

    /**
     * @notice Allows the contract to receive ETH
     */
    receive() external payable {}

    function _beforeRemoveLiquidity(
        address /* sender */,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) internal view override onlyPoolManager returns (bytes4) {
        // If this is not an ETH-TOKEN pool with this hook attached, ignore
        if (!key.currency0.isAddressZero()) return this.beforeRemoveLiquidity.selector;

        // Generate the pool ID from the key
        bytes32 poolId = keccak256(abi.encode(key));

        // Check if the lock period has expired
        uint256 unlockTime = liquidityRemovalLockPeriod[poolId];
        if (block.timestamp < unlockTime) {
            revert LiquidityLockPeriodNotExpired(unlockTime);
        }

        return this.beforeRemoveLiquidity.selector;
    }
}
