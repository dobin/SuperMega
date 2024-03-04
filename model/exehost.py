from typing import Dict, List
import logging
import pefile
from intervaltree import Interval, IntervalTree

from model.defs import *
import pe.pehelper as pehelper
from pe.superpe import SuperPe, PeSection
from model.carrier import Carrier
from model.rangemanager import RangeManager

logger = logging.getLogger("ExeHost")


class PeRelocEntry():
    def __init__(self, rva: int, base_rva: int, type: str):
        self.rva: int = rva
        self.base_rva: int = base_rva
        self.offset: int = rva - base_rva
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
        self.superpe: SuperPe = None

        self.iat: Dict[str, IatEntry] = {}
        self.base_relocs: List[PeRelocEntry] = []
        self.base_reloc_ranges: RangeManager = None

        self.image_base: int = 0
        self.dynamic_base: bool = False
        self.code_section = None
        self.rwx_section = None

        self.ep = None
        self.ep_raw = None


    def init(self):
        logger.info("--[ Analyzing: {}".format(self.filepath))
        self.superpe = SuperPe(self.filepath)

        if self.superpe.arch != "x64":
            raise Exception("Binary is not 64bit: {}".format(self.filepath))

        self.ep = self.superpe.get_entyrpoint()
        self.ep_raw = self.superpe.get_physical_address(self.ep)

        # image base
        self.image_base = self.superpe.pe.OPTIONAL_HEADER.ImageBase

        # dynamic base / ASLR
        if self.superpe.pe.OPTIONAL_HEADER.DllCharacteristics & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']:
            self.dynamic_base = True
        else:
            self.dynamic_base = False

        # Info output: .text virtual address
        self.code_section = self.superpe.get_code_section()
        logger.info("---[ Injectable: Chosen code section: {} at 0x{:X} size: {}".format(
            self.code_section.Name.decode().rstrip('\x00'),
            self.code_section.VirtualAddress,
            self.code_section.Misc_VirtualSize))

        # relocs
        if hasattr(self.superpe.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in self.superpe.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    rva = entry.rva
                    base_rva = entry.base_rva
                    reloc_type = pefile.RELOCATION_TYPE[entry.type][0]
                    self.base_relocs.append(PeRelocEntry(rva, base_rva, reloc_type))
        
        # rwx section
        entrypoint = self.superpe.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in self.superpe.pe.sections:
            if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] and
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
            ):
                if entrypoint > section.VirtualAddress and entrypoint < section.VirtualAddress + section.Misc_VirtualSize:
                    self.rwx_section = section

        # If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
        #pe.parse_data_directories()

        # IAT
        for entry in self.superpe.pe.DIRECTORY_ENTRY_IMPORT:
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
    
    
    def get_relocations_for_section(self, section_name: str) -> List[PeRelocEntry]:
        section: PeSection = self.superpe.get_section_by_name(section_name)
        if section is None:
            return []
        ret = []

        #return [reloc for reloc in self.base_relocs if reloc.base_rva == section.virt_addr]
        for reloc in self.base_relocs:
            reloc_addr = reloc.rva
            if reloc_addr >= section.virt_addr and reloc_addr < section.virt_addr + section.virt_size:
                ret.append(reloc)
        return ret
    

    def get_rdata_relocmanager(self) -> RangeManager:
        section = self.superpe.get_section_by_name(".rdata")
        relocs = self.get_relocations_for_section(".rdata")
        #print("Relocs for .rdata: {} of {}".format(len(relocs), len(self.base_relocs)))

        rm = RangeManager(section.virt_addr, section.virt_addr + section.virt_size)
        for reloc in relocs:
            # Reloc destination is probably 8 bytes
            # But i add another 8 to skip over small holes (common in .rdata)
            rm.add_range(reloc.rva, reloc.rva + 8 + 8)
        rm.merge_overlaps()
        return rm

    
    def has_all_carrier_functions(self, carrier: Carrier):
            is_ok = True
            for iat_entry in carrier.iat_requests:
                addr = self.get_vaddr_of_iatentry(iat_entry.name)
                if addr == 0:
                    logging.info("---( Function not available as import: {}".format(iat_entry.name))
                    is_ok = False
            return is_ok