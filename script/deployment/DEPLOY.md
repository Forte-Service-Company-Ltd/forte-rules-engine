## Forte Rules Engine Deployment

[![Project Version][version-image]][version-url]

### Building

To build and install dependencies, run the following commands:

```bash
npm install
forge soldeer install
forge build
```

### Dependencies

In order to deploy the engine, there are some other requirements. First, a Python virtual environment is needed to install the Python requirements. We'll also set the env source now.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
source .env
```

### Deployment

The following section will run through the deployment process of the Forte Rules Engine.

#### Environment Configuration

Before deploying, configure your environment variables in the `.env` file:

```bash
# Deployment Configuration
DEPLOYER_PRIVATE_KEY=0x1234567890abcdef...  # Private key of the deploying account
DESIRED_DEPLOYMENT_ADDRESS=0x742d35Cc6634C0532925a3b8D400414004C07f5F  # Target deployment address
ETH_RPC_URL=https://mainnet.infura.io/v3/your-project-id  # RPC URL for target chain
GAS_NUMBER=20000000000  # Gas price in wei (optional)
```

**Important**:

- Set `DEPLOYER_PRIVATE_KEY` to the private key of the account that will deploy the contracts
- Set `DESIRED_DEPLOYMENT_ADDRESS` to your preferred deployment address
- Set `ETH_RPC_URL` to the RPC endpoint of your target blockchain network
- Ensure the deployer account has sufficient funds for gas fees


#### Deployment Script

```bash
# Source environment variables
source .env
```

#### Direct Forge Deployment Using Bash Script

This method deploys the Forte Rules Engine contracts directly using Forge via a provided bash script. Ensure your environment variables are configured as described above before running the script.
```bash
bash script/deployment/SimpleDeploy.sh
```

[version-image]: https://img.shields.io/badge/Version-0.9.2-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/Forte-Service-Company-Ltd/forte-rules-engine
