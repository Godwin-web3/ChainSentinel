import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY", "")

# Timeouts
HTTP_TIMEOUT = 30
RPC_TIMEOUT = 10

# Analysis
MAX_PROXY_DEPTH = 5
BYTECODE_MIN_LENGTH = 10

# Slither
SLITHER_TIMEOUT = 120

# Anvil fork
ANVIL_PORT = 8545
ANVIL_TIMEOUT = 60

# Output
REPORTS_DIR = "output/reports"
TEMP_DIR = "/tmp/exploit-agent"

# Supported proxy types
PROXY_SLOTS = {
    "eip1967_impl": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "eip1967_beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    "openzeppelin_impl": "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
}
