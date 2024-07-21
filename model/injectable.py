from typing import Dict, List
import logging
import pefile

from model.defs import *
from pe.superpe import SuperPe, PeSection


logger = logging.getLogger("Injectable")


class IatRequest():
    def __init__(self, name: str, placeholder: bytes):
        self.name: str = name           # Function Name, like "VirtualAlloc"
        self.references: List[bytes] = []
        self.add_reference(placeholder)

    def add_reference(self, placeholder): 
        self.references.append(placeholder)


class DataReuseReference(): 
    def __init__(self, placeholder: bytes, register: str):
        self.placeholder: bytes = placeholder
        self.register: str = register


class DataReuseEntry():
    def __init__(self, string_ref: str, in_code: bool = False):
        self.string_ref: str = string_ref  # "$SG72513"
        self.data: bytes = b''             # the content/data
        self.addr: int = 0                 # where content/data is stored
        self.in_code: bool = in_code       # is the data in code section

        self.references: List[DataReuseReference] = []


    def add_reference(self, placeholder, register): 
        self.references.append(DataReuseReference(placeholder, register))


class Injectable():
    def __init__(self, exe_file: str):
        self.iat_requests: List[IatRequest] = []
        self.reusedata_fixups: List[DataReuseEntry] = []
        self.exe_filepath: str = exe_file
        self.superpe: SuperPe = None

    def init(self):
        self.superpe = SuperPe(self.exe_filepath)


    # IAT

    def add_iat_request(self, func_name: str, placeholder: bytes):
        # existing?
        for iat in self.iat_requests:
            if iat.name == func_name:
                iat.add_reference(placeholder)
                return

        # new
        self.iat_requests.append(IatRequest(func_name, placeholder))

    def get_all_iat_requests(self) -> List[IatRequest]:
        return self.iat_requests

    def get_unresolved_iat(self):
        """Returns a list of IAT entries not available in the PE file"""
        functions = []
        for iat in self.iat_requests:
            if self.superpe.get_vaddr_of_iatentry(iat.name) == None:
                functions.append(iat.name)
        return functions


    # Data Reuse

    def add_datareuse_fixup(self, fixup: DataReuseEntry):
        logger.info("---( Add datareuse: {}".format(fixup.string_ref))
        self.reusedata_fixups.append(fixup)

    def get_all_reusedata_fixups(self) -> List[DataReuseEntry]:
        return self.reusedata_fixups

    def get_reusedata_fixup(self, string_ref) -> DataReuseEntry:
        for entry in self.reusedata_fixups:
            if entry.string_ref == string_ref:
                return entry
        return None
        