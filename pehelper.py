import sys
import pefile
import pprint
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def assemble_and_disassemble_jump(current_address, destination_address):
    #print("    Make jmp from 0x{:X} to 0x{:X}".format(
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
    #print(f"Machine Code: {' '.join(f'{byte:02x}' for byte in machine_code)}")
    #print(f"Disassembled: {disassembled.mnemonic} {disassembled.op_str}")
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
            #pprint.pprint(imp.keys())
            #print(type(imp))

            #print("{}  {} - 0x{:08X}".format(
            #    dll_name,
            #    imp_name,
            #    imp_addr
            #))

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