from typing import Dict
import logging
import pefile

import pehelper

logger = logging.getLogger("Model")


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


class ExeInfo():
    def __init__(self):
        self.iat_resolves: Dict[str, IatResolve] = {}
        self.image_base = 0
        self.dynamic_base = False

        self.code_virtaddr = 0
        self.code_size = 0
        self.code_section = None

        self.iat = {}
        self.base_relocs = []
        self.rwx_section = None


    def add_capability(self, func_name, placeholder):
        self.iat_resolves[func_name] = IatResolve(
            func_name, placeholder, pehelper.get_addr_for(self.iat, func_name))


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
        self.iat = pehelper.extract_iat(pe)

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


    def get_all_iat_resolvs(self) -> Dict[str, IatResolve]:
        return self.iat_resolves
    
    
    def has_all_functions(self, needs):
        is_ok = True
        for func_name in needs:
            addr = pehelper.get_addr_for(self.iat, func_name)
            if addr == 0:
                logging.warn("Not available as import: {}".format(func_name))
                is_ok = False
        return is_ok
    

    def print(self):
        logger.info("--( Required IAT Resolves: ")
        for _, cap in self.iat_resolves.items():
            if cap.addr == 0:
                logger.info("   {:28} {}".format(cap.name, "N/A"))
            else:
                logger.info("   {:28} 0x{:x}".format(cap.name, cap.addr))
