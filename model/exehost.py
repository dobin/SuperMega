from typing import Dict, List
import logging
import pefile

from model.defs import *
import peparser.pehelper as pehelper
from peparser.superpe import SuperPe
from peparser.misc import get_physical_address

logger = logging.getLogger("ExeHost")


class RelocEntry():
    def __init__(self, rva: int, base_rva: int, type: str):
        self.rva: int = rva
        self.base_rva: int = base_rva
        self.type: str = type


class IatEntry():
    def __init__(self, dll_name: str, func_name: str, iat_vaddr: int):
        self.dll_name: str = dll_name
        self.func_name: str = func_name
        self.iat_vaddr: int = iat_vaddr


class ExeHost():
    def __init__(self, filepath: FilePath):
        self.filepath: FilePath = filepath

        # we keep this open
        # And modify the EXE through this at the end
        self.pe: pefile.PE = None
        self.superpe: SuperPe = None

        self.iat: Dict[str, IatEntry] = {}
        self.base_relocs = []

        self.image_base: int = 0
        self.dynamic_base: bool = False

        self.code_virtaddr: int = 0
        self.code_size: int = 0
        self.code_section = None
        
        self.rwx_section = None

        self.ep = None
        self.ep_raw = None


    def init(self):
        logger.info("--[ Analyzing: {}".format(self.filepath))

        pe = pefile.PE(self.filepath)
        self.pe = pe
        self.superpe = SuperPe(pe)
        self.superpe.init()

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
        
        # rwx section
        entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in pe.sections:
            if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] and
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
            ):
                if entrypoint > section.VirtualAddress and entrypoint < section.VirtualAddress + section.Misc_VirtualSize:
                    self.rwx_section = section

        # If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
        #pe.parse_data_directories()

        # IAT
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                dll_name = entry.dll.decode('utf-8')
                if imp.name == None:
                    continue
                imp_name = imp.name.decode('utf-8')
                imp_addr = imp.address

                if not dll_name in self.iat:
                    self.iat[dll_name] = []

                self.iat[dll_name].append(IatEntry(dll_name, imp_name, imp_addr))
        

    def get_vaddr_of_iatentry(self, func_name: str) -> int:
        for dll_name in self.iat:
            for entry in self.iat[dll_name]:
                if entry.func_name == func_name:
                    return entry.iat_vaddr
        return None
    