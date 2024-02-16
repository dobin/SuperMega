from typing import Dict
import logging
import pefile

import pehelper

logger = logging.getLogger("Model")


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


class ExeInfo():
    def __init__(self, capabilities):
        self.capabilities: Dict[str, Capability] = {}
        self.image_base = 0
        self.dynamic_base = False

        self.code_virtaddr = 0
        self.code_size = 0
        self.code_section = None

        self.iat = {}
        self.base_relocs = []
        self.rwx_section = None

        for cap in capabilities:
            self.capabilities[cap] = Capability(cap)


    def parse_from_exe(self, filepath):
        pe = pefile.PE(filepath)

        if pe.FILE_HEADER.Machine != 0x8664:
            raise Exception("Binary is not 64bit: {}".format(filepath))

        # image base
        self.image_base = pe.OPTIONAL_HEADER.ImageBase

        # dynamic base / ASLR
        if pe.OPTIONAL_HEADER.DllCharacteristics & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']:
            self.dynamic_base = True
        else:
            self.dynamic_base = False

        # .text virtual address
        self.code_section = pehelper.get_code_section(pe)
        self.code_virtaddr = self.code_section.VirtualAddress
        self.code_rawsize = self.code_section.SizeOfRawData

        # iat
        iat = pehelper.extract_iat(pe) 
        for _, cap in self.capabilities.items():
            cap.addr = pehelper.get_addr_for(iat, cap.name)
        self.iat = iat

        # relocs
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    entry_rva = entry.rva
                    reloc_type = pefile.RELOCATION_TYPE[entry.type][0]
                    self.base_relocs.append({
                        'rva': entry_rva,
                        'type': reloc_type,
                    })
        
        # rwx
        self.rwx_section = pehelper.get_rwx_section(pe)


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
        logger.info("--( Capabilities: ")
        for _, cap in self.capabilities.items():
            if cap.addr == 0:
                logger.info("   {:28} {}".format(cap.name, "N/A"))
            else:
                logger.info("   {:28} 0x{:x}".format(cap.name, cap.addr))
