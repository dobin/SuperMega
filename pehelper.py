import sys
import pefile
import pprint
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import logging

from model.defs import *

logger = logging.getLogger("PEHelper")


def extract_code_from_exe(exe_file: FilePath) -> bytes:
    pe = pefile.PE(exe_file)
    section = get_code_section(pe)
    data: bytes = section.get_data()
    data = remove_trailing_null_bytes(data)
    logger.debug("---[ Extract code section size: {} / {}".format(
        len(data), section.Misc_VirtualSize))
    pe.close()
    return data


def write_code_section(exe_file: FilePath, new_data: bytes):
    pe = pefile.PE(exe_file)
    section = get_code_section(pe)
    file_offset = section.PointerToRawData
    with open(exe_file, 'r+b') as f:
        f.seek(file_offset)
        f.write(new_data)
    pe.close()

def get_code_section(pe: pefile.PE) -> pefile.SectionStructure:
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for sect in pe.sections:
        if sect.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
            if entrypoint >= sect.VirtualAddress and entrypoint <= sect.VirtualAddress + sect.Misc_VirtualSize:
                return sect
    raise Exception("Code section not found")


# RWX
def get_rwx_section(pe: pefile.PE) -> pefile.SectionStructure:
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and
            section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] and
            section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
        ):
            if entrypoint > section.VirtualAddress and entrypoint < section.VirtualAddress + section.Misc_VirtualSize:
                return section
    return None


# keystone/capstone stuff

def assemble_lea(current_address: int, destination_address: int, reg: str) -> bytes:
    print("LEAH: 0x{:X} - 0x{:X} = 0x{:X}".format(
        current_address, destination_address, destination_address - current_address))
    offset = destination_address - current_address
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, _ = ks.asm(f"lea {reg}, qword ptr ds:[{offset}]")
    machine_code = bytes(encoding)
    return machine_code

def assemble_and_disassemble_jump(current_address: int, destination_address: int) -> bytes:
    #logger.info("    Make jmp from 0x{:X} to 0x{:X}".format(
    #    current_address, destination_address
    #))
    # Calculate the relative offset
    # For a near jump, the instruction length is typically 5 bytes (E9 xx xx xx xx)
    offset = destination_address - current_address
    
    # Assemble the jump instruction using Keystone
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, _ = ks.asm(f"call qword ptr ds:[{offset}]")
    machine_code = bytes(encoding)
    
    # Disassemble the machine code using Capstone
    #cs = Cs(CS_ARCH_X86, CS_MODE_64)
    #disassembled = next(cs.disasm(machine_code, current_address))
    #logger.info(f"Machine Code: {' '.join(f'{byte:02x}' for byte in machine_code)}")
    #logger.info(f"Disassembled: {disassembled.mnemonic} {disassembled.op_str}")
    return machine_code


# IAT Stuff

def extract_iat(pe: pefile.PE):
    iat = {}

    # If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
    #pe.parse_data_directories()

    # Retrieve the IAT entries from the PE file
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            dll_name = entry.dll.decode('utf-8')
            if imp.name == None:
                continue
            imp_name = imp.name.decode('utf-8')
            imp_addr = imp.address

            if not dll_name in iat:
                 iat[dll_name] = []

            iat[dll_name].append({
                 "dll_name": dll_name,
                 "func_name": imp_name,
                 "func_addr": imp_addr
            })
    
    return iat


def get_addr_for(iat, func_name: str) -> int:
    for dll_name in iat:
        for entry in iat[dll_name]:
            if entry["func_name"] == func_name:
                return entry["func_addr"]
    return 0


## Utils

def remove_trailing_null_bytes(data: bytes) -> bytes:
    for i in range(len(data) - 1, -1, -1):
        if data[i] != b'\x00'[0]:  # Check for a non-null byte
            return data[:i + 1]
    return b''  # If the entire sequence is null bytes
