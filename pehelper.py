import sys
import pefile
import pprint
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import logging

logger = logging.getLogger("PEHelper")


def get_code_section(pe):
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    for sect in pe.sections:
        name = sect.Name.decode()
        #logger.info("Checking: {} and 0x{:x}".format(name, sect.Characteristics))

        if sect.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
            if entrypoint >= sect.VirtualAddress and entrypoint <= sect.VirtualAddress + sect.SizeOfRawData:
                return sect
            #else:
            #    logger.info("NOOO: 0x{:x} 0x{:x} 0x{:x}".format(
            #        entrypoint,
            #        sect.VirtualAddress,
            #        sect.VirtualAddress + sect.SizeOfRawData,
            #    ))

    return None


# RWX
def get_rwx_section(pe):
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and
            section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] and
            section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
        ):
            #name = section.Name.decode().rstrip('\x00')
            if entrypoint > section.VirtualAddress and entrypoint < section.VirtualAddress + section.SizeOfRawData:
                return section
    return None


# keystone/capstone stuff

def assemble_and_disassemble_jump(current_address, destination_address):
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

def extract_iat(pe):
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


def get_addr_for(iat, func_name):
    for dll_name in iat:
        for entry in iat[dll_name]:
            if entry["func_name"] == func_name:
                return entry["func_addr"]
    return 0


def resolve_iat_capabilities(needed_capabilities, inject_exe):
    pe = pefile.PE(inject_exe)
    iat = extract_iat(pe) 
    for _, cap in needed_capabilities.items():
        cap.addr = get_addr_for(iat, cap.name)


def main():
        pe = pefile.PE(sys.argv[1])
        iat = extract_iat(pe)


if __name__ == "__main__":
    main()