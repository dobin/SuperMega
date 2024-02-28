import pefile
import capstone
from enum import IntEnum
import logging

from helper import hexdump

logger = logging.getLogger("MyPe")


class MyPe():
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    IMAGE_DIRECTORY_ENTRY_TLS = 9

    IMAGE_REL_BASED_ABSOLUTE              = 0
    IMAGE_REL_BASED_HIGH                  = 1
    IMAGE_REL_BASED_LOW                   = 2
    IMAGE_REL_BASED_HIGHLOW               = 3
    IMAGE_REL_BASED_HIGHADJ               = 4
    IMAGE_REL_BASED_DIR64                 = 10


    def __init__(self):
        self.pe = None

    def openFile(self, infile):
        self.pe = pefile.PE(infile, fast_load=False)
        self.pe.parse_data_directories()

        self.ptrSize = 4
        self.arch = self.getFileArch()
        if self.arch == 'x64': 
            self.ptrSize = 8


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
        relocsIndex = self.getSectionIndexByDataDir(MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
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

        imageBaseRelocType = MyPe.IMAGE_REL_BASED_HIGHLOW
        if self.arch == 'x64':
            imageBaseRelocType = MyPe.IMAGE_REL_BASED_DIR64

        logger.info('Adding new relocations to backdoored PE file...')

        relocsSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        relocsIndex = self.getSectionIndexByDataDir(MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        sizeOfReloc = 2 * len(relocs) + 2 * 4

        if sizeOfReloc >= self.getRemainingRelocsDirectorySize():
            self.logger.warn('WARNING! Cannot add any more relocations to this file. Probably TLS Callback execution technique wont work.')
            self.logger.warn('         Will try disabling relocations on output file. Expect corrupted executable though!')

            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0
            return

        relocDirRva = self.pe.sections[relocsIndex].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[MyPe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeOfReloc

        # VirtualAddress
        self.pe.set_dword_at_rva(addr + relocsSize, pageRva)

        # SizeOfBlock
        self.pe.set_dword_at_rva(addr + relocsSize + 4, sizeOfReloc)

        logger.info(f'Adding {len(relocs)} relocations for Page RVA 0x{pageRva:x} - size of block: 0x{sizeOfReloc:x}')

        i = 0
        for reloc in relocs:
            reloc_offset = (reloc - pageRva)
            reloc_type = imageBaseRelocType << 12

            relocWord = (reloc_type | reloc_offset)
            self.pe.set_word_at_rva(relocDirRva + relocsSize + 8 + i * 2, relocWord)
            logger.info(f'\tReloc{i} for addr 0x{reloc:x}: 0x{relocWord:x} - 0x{reloc_offset:x} - type: {imageBaseRelocType}')
            i += 1


    ## Helpers

    def get_entyrpoint(self) -> int:
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def set_entrypoint(self, entrypoint: int):
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = entrypoint


    def write(self, outfile: str):
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
                    logger.debug('\t' * (depth+1) + f' -> OP_IMM: 0x{operand.value.imm:x}')
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
