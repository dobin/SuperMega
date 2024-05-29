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

        # Default keys
        self.xor_key: int = 0x42
        self.xor_key2: bytes = b"\x13\x37"

        self.data_fixups = None
        self.data_fixup_entries = None


    def getConfigPath(self):
        return CONFIG_FILE
    
    def getConfig(self):
        return self.data
    
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
            
        # keys
        if self.data["xor_key"] == "":
            self.xor_key = random.randint(0, 255)
        else:
            self.xor_key = self.data["xor_key"]
        if self.data["xor_key2"] == "":
            self.xor_key = os.urandom(2)
        else:
            self.xor_key = self.data["xor_key2"]
        logger.info("XOR Key: {}  XOR2 Key: {}".format(
            self.xor_key, self.xor_key2
        ))

    def get(self, value):
        return self.data.get(value, "")

config = Config()