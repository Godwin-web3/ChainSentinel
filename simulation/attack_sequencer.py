from web3 import Web3
from typing import Optional
from simulation.fork_manager import ForkManager
from utils.logger import log

# Common attack primitives
FLASH_LOAN_PROVIDERS = {
    "aave_v3": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "balancer": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    "uniswap_v3": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
}

ERC20_ABI = [
    {"inputs": [{"name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "type": "function", "stateMutability": "view"},
    {"inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "approve", "outputs": [{"name": "", "type": "bool"}], "type": "function", "stateMutability": "nonpayable"},
    {"inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function", "stateMutability": "nonpayable"},
]

class AttackSequencer:
    def __init__(self, fork: ForkManager):
        self.fork = fork
        self.w3 = fork.w3
        self.attacker = fork.get_accounts()[0]
        self.sequences = []

    def snapshot(self) -> dict:
        if not self.w3:
            return {}
        return {
            "block": self.w3.eth.block_number,
            "attacker_eth": self.fork.get_balance(self.attacker),
        }

    def get_token_balance(self, token: str, address: str) -> int:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(token),
                abi=ERC20_ABI
            )
            return contract.functions.balanceOf(
                Web3.to_checksum_address(address)
            ).call()
        except Exception as e:
            log.error(f"Token balance failed: {e}")
            return 0

    def send_eth(self, to: str, amount_eth: float) -> Optional[str]:
        try:
            tx_hash = self.w3.eth.send_transaction({
                "from": self.attacker,
                "to": Web3.to_checksum_address(to),
                "value": self.w3.to_wei(amount_eth, "ether"),
                "gas": 21000,
            })
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            log.success(f"ETH sent: {amount_eth} ETH to {to}")
            return tx_hash.hex()
        except Exception as e:
            log.error(f"ETH send failed: {e}")
            return None

    def call_function(self, address: str, abi: list, function: str,
                      args: list = [], value_eth: float = 0) -> Optional[dict]:
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=abi
            )
            fn = getattr(contract.functions, function)
            tx = fn(*args).build_transaction({
                "from": self.attacker,
                "value": self.w3.to_wei(value_eth, "ether"),
                "gas": 500000,
                "nonce": self.w3.eth.get_transaction_count(self.attacker),
            })
            tx_hash = self.w3.eth.send_transaction(tx)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            log.success(f"Called {function} — gas used: {receipt['gasUsed']}")
            return {
                "tx_hash": tx_hash.hex(),
                "gas_used": receipt["gasUsed"],
                "status": receipt["status"],
                "block": receipt["blockNumber"],
            }
        except Exception as e:
            log.error(f"Function call failed: {e}")
            return None

    def check_profit(self, token: str, initial_balance: int) -> dict:
        current = self.get_token_balance(token, self.attacker)
        profit = current - initial_balance
        return {
            "initial": initial_balance,
            "current": current,
            "profit": profit,
            "profitable": profit > 0
        }

    def run_sequence(self, steps: list) -> dict:
        log.section("Running Attack Sequence")
        before = self.snapshot()
        results = []

        for i, step in enumerate(steps):
            log.info(f"Step {i+1}: {step.get('description', 'unknown')}")
            action = step.get("action")

            if action == "send_eth":
                tx = self.send_eth(step["to"], step["amount"])
                results.append({"step": i+1, "tx": tx, "success": tx is not None})

            elif action == "call":
                tx = self.call_function(
                    step["address"],
                    step["abi"],
                    step["function"],
                    step.get("args", []),
                    step.get("value", 0)
                )
                results.append({"step": i+1, "tx": tx, "success": tx is not None})

            else:
                log.warn(f"Unknown action: {action}")
                results.append({"step": i+1, "success": False})

        after = self.snapshot()

        eth_profit = after["attacker_eth"] - before["attacker_eth"]

        return {
            "steps": results,
            "eth_profit_wei": eth_profit,
            "eth_profit": eth_profit / 10**18,
            "profitable": eth_profit > 0,
            "before": before,
            "after": after,
        }
