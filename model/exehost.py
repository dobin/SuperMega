from typing import Dict, List
import logging
import pefile

from model.defs import *
import peparser.pehelper as pehelper
from peparser.misc import get_physical_address

logger = logging.getLogger("ExeHost")


class IatResolve():
    def __init__(self, name: str, placeholder: bytes, addr: int):
        self.name: str = name           # Function Name, like "VirtualAlloc"
        self.id: bytes = placeholder    # Random bytes
        self.addr: int = addr           # The address of the IAT entry (incl. image_base)


    def __str__(self) -> str:
        return "0x{:X}: {} ({})".format(
            self.addr,
            self.name,
            self.id
        )


class ExeHost():
    def __init__(self, filepath: FilePath):
        self.filepath: FilePath = filepath

        self.iat_resolves: Dict[str, IatResolve] = {}
        self.iat = {}

        self.image_base = 0
        self.dynamic_base = False

        self.code_virtaddr = 0
        self.code_size = 0
        self.code_section = None

        
        self.base_relocs = []
        self.rwx_section = None

        self.ep = None
        self.ep_raw = None



    def init(self):
        logger.info("--[ Analyzing: {}".format(self.filepath))
        pe = pefile.PE(self.filepath)

        if pe.FILE_HEADER.Machine != 0x8664:
            raise Exception("Binary is not 64bit: {}".format(self.filepath))

        self.ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.ep_raw = get_physical_address(pe, self.ep)

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
        self.code_size = self.code_section.Misc_VirtualSize
        logger.info("---[ Injectable: Chosen code section: {} at 0x{:x} size: {}".format(
            self.code_section.Name.decode().rstrip('\x00'),
            self.code_virtaddr,
            self.code_size))

        # iat
        self.iat = self.extract_iat(pe)

        # relocs
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    rva = entry.rva
                    base_rva = entry.base_rva
                    reloc_type = pefile.RELOCATION_TYPE[entry.type][0]
                    self.base_relocs.append({
                        'rva': rva,
                        'base_rva': base_rva,
                        'type': reloc_type,
                    })
        
        # rwx
        self.rwx_section = pehelper.get_rwx_section(pe)


    ## IAT related

    def add_iat_resolve(self, func_name, placeholder):
        self.iat_resolves[func_name] = IatResolve(
            func_name, placeholder, self._get_addr_of_iat_function(func_name))


    def get_all_iat_resolvs(self) -> Dict[str, IatResolve]:
        return self.iat_resolves
    
    
    def has_all_iat_functions(self, needed_functions: List[str]) -> bool:
        is_ok = True
        for func_name in needed_functions:
            addr = self._get_addr_of_iat_function(func_name)
            if addr == 0:
                logging.info("---( Function not available as import: {}".format(func_name))
                is_ok = False
        return is_ok
    

    def _get_addr_of_iat_function(self, func_name: str) -> int:
        for dll_name in self.iat:
            for entry in self.iat[dll_name]:
                if entry["func_name"] == func_name:
                    return entry["func_addr"]
        return 0
    
    def extract_iat(self, pe: pefile.PE):
        iat = {}

        # If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
        #pe.parse_data_directories()

        # Retrieve the IAT entries from the PE file
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                dll_name = entry.dll.decode('utf-8')
                if imp.name == None:
                    continue
                imp_name = imp.name.decode('utf-8')
                imp_addr = imp.address

                if not dll_name in iat:
                    iat[dll_name] = []

                iat[dll_name].append({
                    "dll_name": dll_name,
                    "func_name": imp_name,
                    "func_addr": imp_addr
                })
        
        return iat

    ## Other

    def print(self):
        logger.info("--( Required IAT Resolves: ")
        for _, cap in self.iat_resolves.items():
            if cap.addr == 0:
                logger.info("   {:28} {}".format(cap.name, "N/A"))
            else:
                logger.info("   {:28} 0x{:x}".format(cap.name, cap.addr))
