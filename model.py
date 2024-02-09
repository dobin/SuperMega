from typing import Dict
import pehelper
import pefile
from enum import Enum

class AllocStyle(Enum):
    RWX = 1
    RW_X = 2
    REUSE = 3

class ExecStyle(Enum):
    CALL = 1,
    JMP = 2,
    FIBER = 3,

class CopyStyle(Enum):
    SIMPLE = 1

class DataRefStyle(Enum):
    APPEND = 1

#class InjectStyle(Enum):
    
class SourceStyle(Enum):
    peb_walk = 1
    iat_reuse = 2


class Capability():
    def __init__(self, name):
        self.name = name
        self.id: bytes = b""
        self.addr: int = 0


    def __str__(self):
        return "0x{:X}: {} ({})".format(
            self.addr,
            self.name,
            self.id
        )


class ExeCapabilities():
    def __init__(self, capabilities):
        self.capabilities: Dict[str, Capability] = {}
        self.image_base = 0
        self.text_virtaddr = 0

        for cap in capabilities:
            self.capabilities[cap] = Capability(cap)


    def parse_from_exe(self, filepath):
        pe = pefile.PE(filepath)

        # image base
        self.image_base = pe.OPTIONAL_HEADER.ImageBase

        # .text virtual address
        for section in pe.sections:
            if section.Name.decode().rstrip('\x00') == '.text':
                self.text_virtaddr = section.VirtualAddress

        # iat
        iat = pehelper.extract_iat(pe) 
        for _, cap in self.capabilities.items():
            cap.addr = pehelper.get_addr_for(iat, cap.name)


    def get(self, func_name):
        if not func_name in self.capabilities:
            return None
        if self.capabilities[func_name].addr == 0:
            return None
        
        return self.capabilities[func_name]
    

    def get_all(self) -> Dict[str, Capability]:
        return self.capabilities

    
    def has_all(self):
        needs = [ 'GetEnvironmentVariableW', 'VirtualAlloc']

        for need in needs: 
            if not need in self.capabilities:
                return False
            if self.capabilities[need].addr == 0:
                return False

        return True


    def print(self):
        print("--( Capabilities: ")
        for _, cap in self.capabilities.items():
            print("  " + str(cap))