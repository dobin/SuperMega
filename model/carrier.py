from typing import Dict, List
import logging
import pefile

from model.defs import *
from pe.superpe import SuperPe, PeSection


logger = logging.getLogger("Carrier")


class IatRequest():
    def __init__(self, name: str, placeholder: bytes):
        self.name: str = name           # Function Name, like "VirtualAlloc"
        self.placeholder: bytes = placeholder    # Random bytes as placeholder


class DataReuseEntry():
    def __init__(self, string_ref: str):
        self.string_ref: str = string_ref  # "$SG72513"

        self.register: str = ""  # "rcx"
        self.randbytes: bytes = b""  # placeholder
        self.data: bytes = b''
        self.addr: int = 0


class Carrier():
    def __init__(self, exe_file: str):
        self.iat_requests: List[IatRequest] = []
        self.reusedata_fixups: List[DataReuseEntry] = []
        self.exe_filepath: str = exe_file
        self.superpe: SuperPe = None


    def init(self):
        self.superpe = SuperPe(self.exe_filepath)


    def get_unresolved_iat(self):
        """Returns a list of IAT entries not available in the PE file"""
        functions = []
        for iat in self.iat_requests:
            if self.superpe.get_vaddr_of_iatentry(iat.name) == None:
                functions.append(iat.name)
        return functions


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
        