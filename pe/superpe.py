import pefile
import capstone
from enum import IntEnum
import logging
from typing import List

from utils import hexdump
from model.defs import *

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
        self.pe_sections: List[PeSection] = []
        self.pe = pefile.PE(infile, fast_load=False)
        for section in self.pe.sections:
            self.pe_sections.append(PeSection(section))

        self.pe.parse_data_directories()

        self.ptrSize = 4
        self.arch = self.getFileArch()
        if self.arch == 'x64': 
            self.ptrSize = 8
    

    def get_physical_address(self, virtual_address):
        # Iterate through the section headers to find which section contains the VA
        for section in self.pe.sections:
            # Check if the VA is within the range of this section
            if section.VirtualAddress <= virtual_address < section.VirtualAddress + section.Misc_VirtualSize:
                # Calculate the difference between the VA and the section's virtual address
                virtual_offset = virtual_address - section.VirtualAddress
                # Add the difference to the section's pointer to raw data
                return virtual_offset
                #physical_address = section.PointerToRawData + virtual_offset
                #return physical_address
        return None


    def getFileArch(self):
        if self.pe.FILE_HEADER.Machine == 0x014c:
            return "x86"

        if self.pe.FILE_HEADER.Machine == 0x8664:
            return "x64"

        raise Exception("Unsupported PE file architecture.")


    def get_code_section(self):
        entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for sect in self.pe.sections:
            if sect.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
                if entrypoint >= sect.VirtualAddress and entrypoint <= sect.VirtualAddress + sect.Misc_VirtualSize:
                    return sect
        return None
        

    def get_code_section_data(self) -> bytes:
        sect = self.get_code_section()
        return bytes(sect.get_data())
    

    def get_rwx_section(self):
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
    

    def get_base_relocs(self):
        base_relocs = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    rva = entry.rva
                    base_rva = entry.base_rva
                    reloc_type = pefile.RELOCATION_TYPE[entry.type][0]
                    base_relocs.append(PeRelocEntry(rva, base_rva, reloc_type))
        return base_relocs
    

    def get_iat_entries(self):
        iat = {}
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                dll_name = entry.dll.decode('utf-8')
                if imp.name == None:
                    continue
                imp_name = imp.name.decode('utf-8')
                imp_addr = imp.address

                if not dll_name in iat:
                    iat[dll_name] = []
                iat[dll_name].append(IatEntry(dll_name, imp_name, imp_addr))
        return iat


    def write_code_section_data(self, data: bytes):
        sect = self.get_code_section()
        if len(data) != sect.SizeOfRawData:
            logger.error(f'New code section data is larger than the original! {len(data)} != {sect.SizeOfRawData}')
            return
        self.pe.set_bytes_at_offset(sect.PointerToRawData, data)


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


    def getSectionIndexByName(self, name):
        i = 0
        for sect in self.pe.sections:
            if sect.Name.decode().lower().startswith(name.lower()):
                return i
            i += 1

        logger.error(f'Could not find section with name {name}!')
        return -1
    
    
    def addImageBaseRelocations(self, pageRva, relocs):
        assert pageRva > 0

        if not self.pe.has_relocs():
            logger.error("No .reloc section")
            raise(Exception("No .reloc section"))

        imageBaseRelocType = SuperPe.IMAGE_REL_BASED_HIGHLOW
        if self.arch == 'x64':
            imageBaseRelocType = SuperPe.IMAGE_REL_BASED_DIR64

        relocsSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        relocsIndex = self.getSectionIndexByDataDir(SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[SuperPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        sizeOfReloc = 2 * len(relocs) + 2 * 4

        if sizeOfReloc >= self.getRemainingRelocsDirectorySize():
            self.logger.warn('WARNING! Cannot add any more relocations to this file. Probably TLS Callback execution technique wont work.')
            self.logger.warn('         Will try disabling relocations on output file. Expect corrupted executable though!')

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


    ## Helpers

    def get_entyrpoint(self) -> int:
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def set_entrypoint(self, entrypoint: int):
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = entrypoint


    def write_pe_to_file(self, outfile: str):
        self.pe.write(outfile)

    
    def disasmBytes(self, cs, ks, disasmData, startOffset, length, callback = None, maxDepth = 5):
        return self._disasmBytes(cs, ks, disasmData, startOffset, length, callback, maxDepth, 1)


    def printInstr(self, instr, depth):
        _bytes = [f'{x:02x}' for x in instr.bytes[:8]]
        if len(instr.bytes) < 8:
            _bytes.extend(['  ',] * (8 - len(instr.bytes)))

        instrBytes = ' '.join([f'{x}' for x in _bytes])
        logger.debug('\t' * 1 + f'[{instr.address:08x}]\t{instrBytes}' + '\t' * depth + f'{instr.mnemonic}\t{instr.op_str}')


    def _disasmBytes(self, cs, ks, disasmData, startOffset, length, callback, maxDepth, depth):
        if depth > maxDepth:
            return 0

        data = disasmData[startOffset:startOffset + length]

        for instr in cs.disasm(data, startOffset):
            self.printInstr(instr, depth)

            if len(instr.operands) == 1:
                operand = instr.operands[0]

                if operand.type == capstone.CS_OP_IMM:
                    logger.debug('\t' * (depth+1) + f' -> OP_IMM: 0x{operand.value.imm:X}')
                    logger.debug('')

                    if callback:
                        out = callback(cs, ks, disasmData, startOffset, instr, operand, depth)
                        if out != 0:
                            return out

                    if depth + 1 <= maxDepth:
                        out = self._disasmBytes(cs, ks, disasmData, operand.value.imm, length, callback, maxDepth, depth + 1)
                        return out

        if not callback:
            return 1

        return 0
