import json
import hmac
import hashlib
import logging

from encapsulation import AuthToolkit


class ConfigToolkit(AuthToolkit):
    def __init__(self, logger: logging.Logger, config_path: str = "auth.json", config: dict = None):
        self.logger = logger
        if not config:
            with open(config_path) as fp:
                config = json.load(fp)
        if "key_id" in config and "key" in config:
            self.key_id = config["key_id"]
            self.key = config["key"]
            self.logger.info(f"Auth key loaded: {self.key_id}")
        else:
            raise RuntimeError("Key not configured")

    def get_key(self) -> str:
        return self.key_id

    def sign(self, data: bytes) -> bytes:
        s = hmac.new(self.key.encode("utf-8"), data, hashlib.sha1)
        return s.digest()


AUTH_TOOLKIT_INFO = {
    "ConfigToolkit": ConfigToolkit
}
