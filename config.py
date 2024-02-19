import yaml
import os
import logging

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.yaml")

class Config(object):
    def __init__(self):
        self.data = {}
        self.ShowCommandOutput: bool = False
        self.debug: bool = False

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

    def get(self, value):
        return self.data.get(value, "")

config = Config()