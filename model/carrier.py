from typing import Dict, List
import logging

from model.exehost import ExeHost

logger = logging.getLogger("ExeHost")


class IatEntry():
    def __init__(self, name: str, placeholder: bytes):
        self.name: str = name           # Function Name, like "VirtualAlloc"
        self.placeholder: bytes = placeholder    # Random bytes as placeholder



class Carrier():
    def __init__(self):
        self.iat_requests: List[IatEntry] = []


    def init(self):
        pass


    def add_iat_request(self, func_name: str, placeholder: bytes):
        self.iat_requests.append(IatEntry(func_name, placeholder))


    def get_all_iat_requests(self) -> List[IatEntry]:
        return self.iat_requests
