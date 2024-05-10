import sys
import pefile
import pprint
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
import logging

from model.defs import *

logger = logging.getLogger("AsmDisasm")


cs = Cs(CS_ARCH_X86, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN)
cs.detail = True # from RedBackdoorer


ks = Ks(KS_ARCH_X86, KS_MODE_64)

def assemble_lea(current_address: int, destination_address: int, reg: str) -> bytes:
    #print("LEAH: 0x{:X} - 0x{:X} = 0x{:X}".format(
    #    current_address, destination_address, destination_address - current_address))
    offset = destination_address - current_address
    encoding, _ = ks.asm(f"lea {reg}, qword ptr ds:[{offset}]")
    machine_code = bytes(encoding)
    return machine_code


def assemble_relative_call(current_address: int, destination_address: int) -> bytes:
    # Calculate the relative offset
    # For a near jump, the instruction length is typically 5 bytes (E9 xx xx xx xx)
    offset = destination_address - current_address

    # Assemble the jump instruction using Keystone
    encoding, _ = ks.asm(f"call qword ptr ds:[{offset}]")
    machine_code = bytes(encoding)
    
    # Disassemble the machine code using Capstone
    #cs = Cs(CS_ARCH_X86, CS_MODE_64)
    #disassembled = next(cs.disasm(machine_code, current_address))
    #logger.info(f"Machine Code: {' '.join(f'{byte:02x}' for byte in machine_code)}")
    #logger.info(f"Disassembled: {disassembled.mnemonic} {disassembled.op_str}")
    return machine_code


def assemble_relative_jmp(current_address: int, destination_address: int) -> bytes:
    offset = destination_address - current_address
    encoding, _ = ks.asm(f"jmp {offset}")
    machine_code = bytes(encoding)
    return machine_code


def asm_disasm(asm_text, offset=0):
    for instr in cs.disasm(asm_text, offset):
        printInstr(instr)


def printInstr(instr, depth=0):
    _bytes = [f'{x:02x}' for x in instr.bytes[:8]]
    if len(instr.bytes) < 8:
        _bytes.extend(['  ',] * (8 - len(instr.bytes)))
    instrBytes = ' '.join([f'{x}' for x in _bytes])
    logger.info('\t' * 1 + f'    [{instr.address:08x}]\t{instrBytes}' + '\t' * depth + f'{instr.mnemonic}\t{instr.op_str}')
