import subprocess
import time
import os
import signal
from typing import Optional
from web3 import Web3
from config.chains import Chain
from config.settings import ANVIL_PORT, ANVIL_TIMEOUT
from utils.logger import log

class ForkManager:
    def __init__(self, chain: Chain, block_number: Optional[int] = None):
        self.chain = chain
        self.block_number = block_number
        self.process = None
        self.port = ANVIL_PORT
        self.rpc_url = f"http://127.0.0.1:{self.port}"
        self.w3 = None

    def start(self) -> bool:
        log.info(f"Starting Anvil fork of {self.chain.name}...")

        cmd = [
            "anvil",
            "--fork-url", self.chain.rpc_url,
            "--port", str(self.port),
            "--accounts", "10",
            "--balance", "10000",
            "--silent"
        ]

        if self.block_number:
            cmd += ["--fork-block-number", str(self.block_number)]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            # Wait for anvil to be ready
            for i in range(ANVIL_TIMEOUT):
                try:
                    w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                    if w3.is_connected():
                        self.w3 = w3
                        block = w3.eth.block_number
                        log.success(f"Anvil ready at block {block} on {self.rpc_url}")
                        return True
                except:
                    pass
                time.sleep(1)

            log.error("Anvil failed to start in time")
            self.stop()
            return False

        except Exception as e:
            log.error(f"Anvil start failed: {e}")
            return False

    def stop(self):
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
                log.debug("Anvil stopped")
            except Exception as e:
                log.warn(f"Anvil stop warning: {e}")
            finally:
                self.process = None
                self.w3 = None

    def get_balance(self, address: str) -> int:
        if not self.w3:
            return 0
        try:
            return self.w3.eth.get_balance(Web3.to_checksum_address(address))
        except Exception as e:
            log.error(f"Balance fetch failed: {e}")
            return 0

    def get_accounts(self) -> list:
        if not self.w3:
            return []
        try:
            return list(self.w3.eth.accounts)
        except:
            return []

    def call_contract(self, address: str, abi: list, function: str, args: list = []) -> any:
        if not self.w3:
            return None
        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=abi
            )
            fn = getattr(contract.functions, function)
            return fn(*args).call()
        except Exception as e:
            log.error(f"Contract call failed: {e}")
            return None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
