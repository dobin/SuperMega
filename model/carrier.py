from typing import Dict, List
import logging


logger = logging.getLogger("Carrier")


class IatRequest():
    def __init__(self, name: str, placeholder: bytes):
        self.name: str = name           # Function Name, like "VirtualAlloc"
        self.placeholder: bytes = placeholder    # Random bytes as placeholder


class DataReuseEntry():
    def __init__(self, string_ref: str):
        self.string_ref = string_ref  # "$SG72513"

        self.register = ""  # "rcx"
        self.randbytes = b""  # placeholder
        self.data = b''
        self.addr = 0


class Carrier():
    def __init__(self):
        self.iat_requests: List[IatRequest] = []
        self.reusedata_fixups: List[DataReuseEntry] = []


    def init(self):
        pass


    # IAT

    def add_iat_request(self, func_name: str, placeholder: bytes):
        self.iat_requests.append(IatRequest(func_name, placeholder))

    def get_all_iat_requests(self) -> List[IatRequest]:
        return self.iat_requests


    # Data Reuse

    def add_datareuse_fixup(self, fixup: DataReuseEntry):
        self.reusedata_fixups.append(fixup)

    def get_all_reusedata_fixups(self) -> List[DataReuseEntry]:
        return self.reusedata_fixups

    def get_all_reusedata_fixup(self, string_ref) -> DataReuseEntry:
        for entry in self.reusedata_fixups:
            if entry.string_ref == string_ref:
                return entry
        return None
        