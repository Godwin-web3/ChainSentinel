import logging
import sys
from datetime import datetime

class ExploitAgentLogger:
    def __init__(self, name: str = "chainsentinel"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.DEBUG)

            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] %(message)s',
                datefmt='%H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def info(self, msg): self.logger.info(msg)
    def debug(self, msg): self.logger.debug(msg)
    def warn(self, msg): self.logger.warning(msg)
    def error(self, msg): self.logger.error(msg)
    def success(self, msg): self.logger.info(f"✓ {msg}")
    def section(self, msg): self.logger.info(f"\n{'='*50}\n  {msg}\n{'='*50}")

log = ExploitAgentLogger()
