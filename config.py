import yaml
import os
import logging
import random

logger = logging.getLogger("Config")


CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.yaml")

class Config(object):
    def __init__(self):
        self.data = {}
        self.ShowCommandOutput: bool = False
        self.debug: bool = False
        self.has_r2: bool = False
        self.catch_exception: bool = True

        self.data_fixups = None
        self.data_fixup_entries = None

        # Default keys
        self.xor_key: int = 0x42
        self.xor_key2: bytes = b"\x13\x37"

    
    def load(self):
        with open(CONFIG_FILE) as jsonfile:
            try:
                self.data = yaml.safe_load(jsonfile)
            except yaml.YAMLError as e:
                print('Decoding {} as failed with: {}'.format(CONFIG_FILE, e))
                quit()

        if 'server' in os.environ:
            server = os.environ["server"] 
            self.data["server"] = { "server": server }
            print("Using ENV: server={}, overwriting all others from config.yaml".format(
                server))
    
    
    def make_encryption_keys(self):
        # keys
        if self.data["xor_key"] == "":
            self.xor_key = random.randint(0, 255)
        else:
            self.xor_key = self.data["xor_key"]

        if self.data["xor_key2"] == "":
            self.xor_key2 = os.urandom(2)
        else:
            self.xor_key2 = self.data["xor_key2"]

        logger.info("-( Payload encryption keys: XOR: {}  XOR2: {}".format(
            self.xor_key, self.xor_key2
        ))


    def getConfigPath(self):
        return CONFIG_FILE
    

    def getConfig(self):
        return self.data

    def get(self, value):
        return self.data.get(value, "")

config = Config()