import logging

from model import *
from model.defs import *

logger = logging.getLogger("Payload")

class Payload():
    def __init__(self, filepath: FilePath):
        self.payload_path: FilePath = filepath
        self.payload_data: bytes = b""
        self.len: int = 0


    def init(self):
        logging.info("--( Load payload: {}".format(self.payload_path))
        with open(self.payload_path, 'rb') as f:
            self.payload_data = f.read()
        self.len = len(self.payload_data)

