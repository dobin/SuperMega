import pefile
import capstone
import logging
from typing import List, Dict
import random

from model.defs import *
from model.rangemanager import RangeManager

logger = logging.getLogger("superpe")


class PeSection():
    def __init__(self, pefile_section: pefile.SectionStructure):
        self.name: str = pefile_section.Name.rstrip(b'\x00').decode("utf-8")
        self.raw_addr: int = pefile_section.PointerToRawData
        self.raw_size: int = pefile_section.SizeOfRawData
        self.virt_addr: int = pefile_section.VirtualAddress
        self.virt_size: int = pefile_section.Misc_VirtualSize
        self.pefile_section: pefile.SectionStructure = pefile_section


class SuperPe():
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    IMAGE_DIRECTORY_ENTRY_TLS = 9

    IMAGE_REL_BASED_ABSOLUTE              = 0
    IMAGE_REL_BASED_HIGH                  = 1
    IMAGE_REL_BASED_LOW                   = 2
    IMAGE_REL_BASED_HIGHLOW               = 3
    IMAGE_REL_BASED_HIGHADJ               = 4
    IMAGE_REL_BASED_DIR64                 = 10


    def __init__(self, infile: str):
        self.filepath: str = infile
        self.pe_sections: List[PeSection] = []
        self.pe = pefile.PE(infile, fast_load=False)
        for section in self.pe.sections:
            self.pe_sections.append(PeSection(section))

        self.iat_entries: Dict[str, IatEntry] = {}
        self.init_iat_entries()
        
    def init_iat_entries(self):
        self.pe.parse_data_directories()
        self.make_iat_entries()


    ## PE Properties

    def is_dll(self) -> bool:
        return self.filepath.endswith(".dll")
    

    def is_64(self) -> bool:
        if self.pe.FILE_HEADER.Machine == 0x8664:
            return True
        return False
    

    def is_dotnet(self) -> bool:
        # https://stackoverflow.com/questions/45574925/is-there-a-way-to-check-if-an-exe-is-dot-net-with-python-pefile
        entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if entry.VirtualAddress != 0 and entry.Size != 0:
            return True
        return False
    
    
    def get_image_base(self) -> int:
        return self.pe.OPTIONAL_HEADER.ImageBase
    

    def is_dynamic_base(self) -> bool:
        # dynamic base / ASLR
        if self.pe.OPTIONAL_HEADER.DllCharacteristics & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']:
            return True
        else:
            return False
    
    
    ## Entrypoint 

    def get_entrypoint(self) -> int:
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    
    def set_entrypoint(self, entrypoint: int):
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = entrypoint


    ## Section Access

    def get_code_section(self) -> pefile.SectionStructure:
        """Return the section that contains the entrypoint and is executable"""
        entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for sect in self.pe.sections:
            if sect.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
                if entrypoint >= sect.VirtualAddress and entrypoint <= sect.VirtualAddress + sect.Misc_VirtualSize:
                    return sect
        return None
        

    def get_code_section_data(self) -> bytes:
        sect = self.get_code_section()
        return bytes(sect.get_data())
    

    def get_rwx_section(self) -> pefile.SectionStructure:
        # rwx section
        entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in self.pe.sections:
            if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] and
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
            ):
                if entrypoint > section.VirtualAddress and entrypoint < section.VirtualAddress + section.Misc_VirtualSize:
                    return section
        return None


    def get_section_by_name(self, name: str) -> PeSection:
        for section in self.pe_sections:
            if section.name == name:
                return section
        return None
    

    def has_rodata_section(self) -> bool:
        return self.get_section_by_name(".rdata")
    
    
    def write_code_section_data(self, data: bytes):
        sect = self.get_code_section()
        if len(data) != sect.SizeOfRawData:
            logger.error(f'New code section data is larger than the original! {len(data)} != {sect.SizeOfRawData}')
            return
        self.pe.set_bytes_at_offset(sect.PointerToRawData, data)


    def patch_subsystem(self):
        if self.is_dll():
            return
        if self.pe.OPTIONAL_HEADER.Subsystem != pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_GUI']:
            logger.info("PE is not a GUI application. Patching subsystem to GUI")
            self.pe.OPTIONAL_HEADER.Subsystem = pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_GUI']


    ## PE Specific Information

    def get_base_relocs(self) -> List[PeRelocEntry]:
        base_relocs = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    rva = entry.rva
                    base_rva = entry.base_rva
                    reloc_type = pefile.RELOCATION_TYPE[entry.type][0]
                    base_relocs.append(PeRelocEntry(rva, base_rva, reloc_type))
        return base_relocs


    def getSectionIndexByDataDir(self, dirIndex):
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[dirIndex].VirtualAddress

        i = 0
        for sect in self.pe.sections:
            if addr >= sect.VirtualAddress and addr < (sect.VirtualAddress + sect.Misc_VirtualSize):
                return i
            i += 1

        logger.error(f'Could not find section with directory index {dirIndex}!')
        return -1


    def getRemainingRelocsDirectorySize(self):
        relocsIndex = self.getSectionIndexByDataDir(SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        out = self.pe.sections[relocsIndex].SizeOfRawData - self.pe.sections[relocsIndex].Misc_VirtualSize
        return out
    
    
    def addImageBaseRelocations(self, pageRva, relocs):
        assert pageRva > 0

        if not self.pe.has_relocs():
            logger.error("No .reloc section")
            raise(Exception("No .reloc section"))

        if self.is_64():
            imageBaseRelocType = SuperPe.IMAGE_REL_BASED_DIR64
        else:
            # Not really used
            imageBaseRelocType = SuperPe.IMAGE_REL_BASED_HIGHLOW

        relocsSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        relocsIndex = self.getSectionIndexByDataDir(SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        sizeOfReloc = 2 * len(relocs) + 2 * 4

        if sizeOfReloc >= self.getRemainingRelocsDirectorySize():
            self.logger.warning('WARNING! Cannot add any more relocations to this file. Probably TLS Callback execution technique wont work.')
            self.logger.warning('         Will try disabling relocations on output file. Expect corrupted executable though!')

            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0
            return

        relocDirRva = self.pe.sections[relocsIndex].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeOfReloc

        # VirtualAddress
        self.pe.set_dword_at_rva(addr + relocsSize, pageRva)

        # SizeOfBlock
        self.pe.set_dword_at_rva(addr + relocsSize + 4, sizeOfReloc)

        logger.info(f'Adding {len(relocs)} relocations for Page RVA 0x{pageRva:X} - size of block: 0x{sizeOfReloc:X}')
        i = 0
        for reloc in relocs:
            reloc_offset = (reloc - pageRva)
            reloc_type = imageBaseRelocType << 12

            relocWord = (reloc_type | reloc_offset)
            self.pe.set_word_at_rva(relocDirRva + relocsSize + 8 + i * 2, relocWord)
            logger.info(f'\tReloc{i} for addr 0x{reloc:X}: 0x{relocWord:X} - 0x{reloc_offset:X} - type: {imageBaseRelocType}')
            i += 1


    def getExportEntryPoint(self, exportName: str):
        dec = lambda x: '???' if x is None else x.decode() 
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        #self.pe.parse_data_directories(directories=d)

        if self.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            raise Exception('No DLL exports found!')
        
        exports = [(e.ordinal, dec(e.name)) for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]
        chosen_export = None
        for export in exports:
            if export[1].lower() == exportName.lower():
                chosen_export = export
                break
        logger.debug("Export: {} {}".format(chosen_export[0], chosen_export[1]))
        name = chosen_export[1]
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name.decode() == name:
                addr = exp.address
        return addr
    

    def get_exports(self) -> List[str]:
        """Return a list of exported functions (names) from the PE file"""
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        self.pe.parse_data_directories(directories=d)
        if self.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            return []
        res = []
        for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            res.append(e.name.decode())
        return res
    

    def get_exports_full(self) -> List[Dict]:
        """Return a list of exported functions (names) from the PE file"""
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        self.pe.parse_data_directories(directories=d)
        try:
            if self.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
                return []
        except Exception as e:
            logger.debug("get_exports_full(): No exports found in PE")
            return []
        res = []
        for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            a = {
                "name": e.name.decode(),
                "addr": e.address
            }
            res.append(a)
        # sort the exports by address
        res.sort(key=lambda x: x["addr"])

        # calculate the size of each export
        for idx, entry in enumerate(res):
            next_entry = res[idx + 1] if idx + 1 < len(res) else None
            if next_entry is None:
                entry["size"] = 0
            else:
                entry["size"] = next_entry["addr"] - entry["addr"]

        return res
    
    def get_size_of_exported_function(self, dllfunc):
        exports = self.get_exports_full()
        for exp in exports:
            if exp["name"] == dllfunc:
                return exp["size"]
        return None
    

    ## Relocations

    def get_rdata_relocmanager(self) -> RangeManager:
        section = self.get_section_by_name(".rdata")
        relocs = self.get_relocations_for_section(".rdata")
        rm = RangeManager(section.virt_addr, section.virt_addr + section.virt_size)
        for reloc in relocs:
            # Reloc destination is probably 8 bytes
            # But i add another 8 to skip over small holes (common in .rdata)
            rm.add_range(reloc.rva, reloc.rva + 8 + 8)
        rm.merge_overlaps()
        return rm


    def get_relocations_for_section(self, section_name: str) -> List[PeRelocEntry]:
        section: PeSection = self.get_section_by_name(section_name)
        ret = []
        if section is None:
            return ret
        for reloc in self.get_base_relocs():
            reloc_addr = reloc.rva
            if reloc_addr >= section.virt_addr and reloc_addr < section.virt_addr + section.virt_size:
                #logger.info("ADDR: 0x{:X}".format(reloc_addr))
                ret.append(reloc)
        return ret
    

    ## IAT

    def get_vaddr_of_iatentry(self, func_name: str) -> int:
        iat = self.get_iat_entries()
        for dll_name in iat:
            for entry in iat[dll_name]:
                if entry.func_name == func_name:
                    return entry.iat_vaddr
        return None
    

    def get_iat_entries(self) -> Dict[str, IatEntry]:
        return self.iat_entries
    

    def make_iat_entries(self) -> Dict[str, IatEntry]:
        iat = {}
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                dll_name = entry.dll.decode('utf-8').lower()
                if imp.name == None:
                    continue
                imp_name = imp.name.decode('utf-8')
                imp_addr = imp.address

                if not dll_name in iat:
                    iat[dll_name] = []
                iat[dll_name].append(IatEntry(dll_name, imp_name, imp_addr))
        self.iat_entries = iat
    

    def get_replacement_iat_for(self, dll_name: str, func_name: str) -> str:
        dll_name = dll_name.lower()
        iat = self.get_iat_entries()
        if not dll_name in iat:
            raise Exception("DLL not found in IAT")

        possible = []
        for entry in iat[dll_name]:
            if len(entry.func_name) >= len(func_name):
                possible.append(entry.func_name)

        if len(possible) == 0:
            return None
        else:
            # Hope there wont be many collisions
            return random.choice(possible)


    def get_iat_offset_by_name(self, dll_name: str, func_name: str) -> int:
        # Iterate over the imported modules and their imported functions
        encoded_dllname = dll_name.lower()
        encoded_funcname = func_name.lower()

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllname = entry.dll.decode("ascii").rstrip("\x00").lower()
            if dllname != encoded_dllname:
                continue
            for imp in entry.imports:
                # Check if the current import name matches the one we want to change
                funcname = imp.name.decode("ascii").rstrip("\x00").lower()
                if funcname == encoded_funcname:
                    return imp.name_offset
            break
        return None
    
    
    def patch_iat_entry(self, dll_name: str, func_name: str, new_func_name: str):
        offset = self.get_iat_offset_by_name(dll_name, func_name)
        if offset is None:
            raise Exception(f"Import {func_name} not found.")
        
        # Change the import name
        # Here we need to ensure the new name fits within the space allocated to the old name
        if len(new_func_name) > len(func_name):
            raise ValueError("New import name is longer than the original name.")
        
        # Pad the new name with null bytes if it's shorter
        new_name_bytes = new_func_name.encode("ascii") + b'\x00' * (len(func_name) - len(new_func_name))
        
        # Overwrite the name in the file data
        logger.info("    Patch IAT entry at offset 0x{:X} from {} to {}".format(
            offset, func_name, new_name_bytes.decode()))
        self.pe.set_bytes_at_offset(offset, new_name_bytes)


    ## Helpers

    def get_offset_from_rva(self, virtual_address) -> int:
        """Convert a virtual address to a physical address in the PE file"""
        # Iterate through the section headers to find which section contains the VA
        for section in self.pe.sections:
            # Check if the VA is within the range of this section
            if section.VirtualAddress <= virtual_address < section.VirtualAddress + section.Misc_VirtualSize:
                # Calculate the difference between the VA and the section's virtual address
                virtual_offset = virtual_address - section.VirtualAddress
                # Add the difference to the section's pointer to raw data
                physical_address = section.PointerToRawData + virtual_offset
                return physical_address
        return None
    

    def write_pe_to_file(self, outfile: str):
        self.pe.write(outfile)


    def removeSignature(self):
        logger.info('PE executable Authenticode signature remove')
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size

        self.pe.set_bytes_at_rva(addr, b'\x00' * size)

        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0
