from typing import Dict, List
import logging

from model.exehost import DataReuseEntry

logger = logging.getLogger("Carrier")


class IatRequest():
    def __init__(self, name: str, placeholder: bytes):
        self.name: str = name           # Function Name, like "VirtualAlloc"
        self.placeholder: bytes = placeholder    # Random bytes as placeholder



class Carrier():
    def __init__(self):
        self.iat_requests: List[IatRequest] = []
        self.reusedata_fixups: List[DataReuseEntry] = []


    def init(self):
        pass


    def add_iat_request(self, func_name: str, placeholder: bytes):
        self.iat_requests.append(IatRequest(func_name, placeholder))

    def get_all_iat_requests(self) -> List[IatRequest]:
        return self.iat_requests


    def set_datareuse_fixups(self, fixups: List[DataReuseEntry]):
        self.reusedata_fixups = fixups

    def get_all_reusedata_fixups(self) -> List[DataReuseEntry]:
        return self.reusedata_fixups
