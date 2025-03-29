# 🔹 Uniroid - Uniswap Pools on Steroids

Uniroid is an advanced security and utility hook framework for Uniswap V4, leveraging EigenLayer AVS and other oracles to enhance security, optimize trading fees, and automate liquidity management.

## 🛑 Problem Statement

The DeFi ecosystem faces increasing threats from rug pulls, malicious liquidity manipulation, and inefficient trading fees. Uniswap V3 and earlier versions provide excellent liquidity solutions but lack built-in security, automated fee mechanisms, and advanced monitoring tools.

### ⚠️ Current Problems & Limitations

- 🔸 **Rug Pulls & LP Scams**: Over $2.8 billion was lost in crypto-related rug pulls and hacks in 2023 alone.
- 🔸 **No AI-driven risk assessment**: Most DEX pools lack automated vulnerability detection for token contracts.
- 🔸 **Fee inefficiencies**: Static fees do not adapt to market conditions, leading to poor trading experience.
- 🔸 **Lack of automated liquidity management**: LP providers suffer impermanent loss without active rebalancing.
- 🔸 **Delayed response to market threats**: No real-time notifications or AI-based trading pauses for security.

## 💡 How Uniroid Solves These Problems

- ✅ Prevents rug pulls & honeypots with EigenLayer AI-powered risk assessment.
- ✅ Protects liquidity providers with automated LP rebalancing & price security tools.
- ✅ Enhances user engagement via fee-based referral & rewards programs.
- ✅ Integrates real-time notifications for instant alerts on critical events.
- ✅ Monitors trading activity using AI to pause trading during market anomalies.

## 🔐 Key Modules

### 1️⃣ RugPull Protection Module
- ✅ Ensures liquidity provider (LP) security by validating deposits.
- ✅ Verifies token locks & vesting to prevent sudden liquidity withdrawals.
- ✅ Uses EigenLayer AVS AI-based analysis to detect vulnerabilities & honeypots.
- ✅ Restricts liquidity withdrawal conditions for added security.
- ✅ Implements anti-whale measures to prevent large token dumps.

### 2️⃣ Fee Optimization & LP Rebalancing
- ✅ Fee Discounting adjusts trading fees dynamically based on market volatility.
- ✅ LP Rebalancing optimizes liquidity provider positions using on-chain & Chainlink oracle data.
- ✅ Subscription-based fees for premium users & high-frequency traders (HFTs).
- ✅ Nezlobin's Directional Fee adjusts fees based on price movement.

### 3️⃣ Referral Rewards System
- ✅ Fee-based referrals: Share a percentage of trading fees with referrers.
- ✅ Token-based referrals: Custom token rewards for user acquisitions.

### 4️⃣ AI-Driven Monitoring & Security
- ✅ Real-time pool monitoring for security risks & abnormal activities.
- ✅ AI-based market analysis to provide pool optimization suggestions.
- ✅ Auto-trading pause if risk factors trigger alerts.

### 5️⃣ Notification System
- ✅ EigenLayer-based live notifications for real-time event updates.
- ✅ Alerts for important pool activities, security threats, and status changes.
- ✅ Supports Telegram, Email, and other external integrations for direct alerts.

## 🔑 Key Features

- 🚀 EigenLayer AVS AI-driven security monitoring
- 🚀 Smart LP locking and withdrawal restrictions
- 🚀 Automated fee optimization & subscription-based fees
- 🚀 Referral-based trading incentives
- 🚀 Real-time notifications via Telegram, Email, and Webhooks

## 🤖 How AI & Security Mechanisms Improve Trading Efficiency

- ✅ AI-powered vulnerability detection prevents malicious token scams.
- ✅ Automated fee adjustments optimize liquidity and reduce slippage.
- ✅ Intelligent trading pause mechanisms prevent pool drains & attacks.
- ✅ Pattern recognition and predictive analytics ensure better risk assessment.
- ✅ Real-time monitoring and alerts keep LPs and traders informed instantly.

## 📊 AI-Driven Insights & Predictions

- 🔹 **Market Trend Analysis** – Helps traders maximize profits by predicting price swings.
- 🔹 **Risk Scoring for Pools** – AI assigns security ratings for better investment decisions.
- 🔹 **Fee Optimization Suggestions** – AI dynamically adjusts fees for maximizing revenue.
- 🔹 **Impermanent Loss Mitigation** – Predicts potential IL risks and auto-adjusts LP positions.

## 🔗 Built with

- ✔️ **EigenLayer AVS** – AI-powered security & monitoring.
- ✔️ **Foundry** – Smart contract development framework.
- ✔️ **Uniswap V4** – Next-generation AMM protocol.

## ✅ Implemented Features vs. 🚧 Planned Features

### ✅ Currently Implemented

#### RugPull Protection Module
- ✅ Liquidity removal lock period (7-day lock on liquidity withdrawals)
- ✅ Hook enabling/disabling for pools
- ✅ Placeholder for AVS verification (structure ready for integration)
- ✅ Admin controls for security management

#### Referral Rewards System
- ✅ Fee-based referrals with commission sharing (50% of trading fees)
- ✅ Points-based rewards for users and referrers
- ✅ Self-referral protection
- ✅ Blacklisting and whitelisting mechanisms

#### Fee Optimization
- ✅ Premium subscriber fee discounts
- ✅ Dynamic fee adjustments for referrals

#### Token Management
- ✅ Admin-controlled token minting to any address
- ✅ Batch minting capability for efficient distribution
- ✅ Automatic points minting based on user activity

#### Security Controls
- ✅ Admin role management
- ✅ Blacklisting and whitelisting mechanisms
- ✅ Withdrawal restrictions

### 🚧 Planned for Future Implementation

#### RugPull Protection Module
- 🚧 Full EigenLayer AVS integration for AI-based token contract analysis
- 🚧 Automated vesting and token lock verification
- 🚧 Anti-whale measures implementation
- 🚧 Malicious code detection using AI models

#### Fee Optimization & LP Rebalancing
- 🚧 Market volatility-based fee adjustments
- 🚧 LP position rebalancing using Chainlink oracle data
- 🚧 Nezlobin's Directional Fee implementation

#### AI-Driven Monitoring & Security
- 🚧 Real-time pool monitoring for security risks
- 🚧 AI-based market analysis for pool optimization
- 🚧 Auto-trading pause for risk factors

#### Notification System
- 🚧 EigenLayer-based live notifications
- 🚧 External integrations (Telegram, Email)
- 🚧 Real-time alerts for security threats

## 🚀 Future Plans

- 🔹 Expand security practices with advanced threat detection.
- 🔹 Introduce Anonymous Swaps across chains with deep Uniswap liquidity.
- 🔹 Build a standalone swap platform with enhanced security hooks.
- 🔹 Develop a comprehensive frontend dashboard for real-time insights.

## 🛠️ Getting Started

### Prerequisites

- Foundry (Forge, Anvil, Cast)
- Node.js and npm/yarn
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/satyam-raikar/uniroidHook.git
cd uniroidHook
```

2. Install dependencies:
```bash
forge install
```

3. Build the project:
```bash
forge build
```

### Testing

Run the test suite to ensure everything is working correctly:
```bash
forge test -vv
```

#### Local Deployment Testing

Before deploying to a testnet or mainnet, you can test the hook mining and deployment process locally:

```bash
# Test the hook mining and deployment process locally
forge script script/TestLocalDeployment.s.sol -vvv
```

This script:
- Deploys a local Pool Manager
- Mines a salt value to generate a hook address with the correct flags
- Deploys the UniroidHook contract using CREATE2 with the mined salt
- Verifies that the deployed address matches the expected address
- Verifies that the hook address has the correct flags

This is a useful verification step to ensure your deployment process works correctly before deploying to a live network.

### Deployment

Deploying Uniroid Hook involves a two-step process to ensure the contract address has the correct hook flags:

#### Step 1: Mine a Hook Address

First, mine a salt value that will generate a contract address with the correct hook flags:

```bash
# Run the hook address mining script
forge script script/MineHookAddress.s.sol
```

This script will:
- Use the deployer address derived from your private key
- Find a salt that produces a hook address with the correct flags
- Output the salt value to use in deployment

#### Step 2: Deploy the Hook

Once you have the salt, deploy the hook contract:

```bash
# Deploy to Sepolia testnet
forge script script/DeployUniroidHook.s.sol --rpc-url <your_rpc_url> --broadcast --verify
```

For local testing:
```bash
# Deploy to a local Anvil instance
anvil
forge script script/DeployUniroidHook.s.sol --rpc-url http://localhost:8545 --broadcast
```

### Deployed Contracts

#### Sepolia Testnet
- **Pool Manager**: [0xE03A1074c86CFeDd5C142C4F04F1a1536e203543](https://sepolia.etherscan.io/address/0xE03A1074c86CFeDd5C142C4F04F1a1536e203543)
- **UniroidHook**: [0xc459932791d6d2ffaa34f058dccc3ac32dd126c0](https://sepolia.etherscan.io/address/0xc459932791d6d2ffaa34f058dccc3ac32dd126c0)

#### Holesky Testnet
- **Pool Manager**: [0x4fdC9175Bc952e8bDCe2e8cA38d00EAa9dB9a299](https://holesky.etherscan.io/address/0x4fdC9175Bc952e8bDCe2e8cA38d00EAa9dB9a299)
- **UniroidHook**: [0xC12b826a16B1C00A3f68fB70C09AC757A78C26c0](https://holesky.etherscan.io/address/0xc12b826a16b1c00a3f68fb70c09ac757a78c26c0)

### Holesky Deployment

To deploy the UniroidHook contract on Holesky testnet (which doesn't have an official Uniswap V4 deployment), follow these steps:

1. **Deploy the Pool Manager**:
```bash
forge script script/DeployPoolManagerHolesky.s.sol --rpc-url <your_rpc_url> --broadcast -vvv
```

2. **Mine a Hook Address**:
```bash
# Update the MineHookAddress.s.sol script with the Holesky Pool Manager address
forge script script/MineHookAddress.s.sol
```

3. **Deploy the Hook**:
```bash
forge script script/DeployUniroidHookHolesky.s.sol --rpc-url <your_rpc_url> --broadcast -vvv
```

### Environment Setup

Create a `.env` file with the following variables:
```
PRIVATE_KEY=your_private_key
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

Uniroid is here to redefine DeFi security. Stay ahead, stay safe. 🚀
