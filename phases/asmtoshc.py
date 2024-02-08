import pefile

from helper import *
from config import config


def make_shc_from_asm(asm_file, exe_file, shc_file):
    print("--[ Assemble to exe: {} -> {} -> {} ]".format(asm_file, exe_file, shc_file))

    print("---[ Assemble ASM to EXE: {} -> {} ]".format(asm_file, exe_file))
    run_process_checkret([
        config.get("path_ml64"),
        asm_file,
        "/link",
        "/OUT:{}".format(exe_file),
        "/entry:AlignRSP"
    ])
    if not os.path.isfile(exe_file):
        print("Error")
        return

    print("---[ EXE to SHC: {} -> {} ]".format(exe_file, shc_file))
    code = get_code_section(exe_file)
    with open(shc_file, 'wb') as f:
        f.write(code)

    return code
    #print("---[ Shellcode from {} written to: {}  (size: {}) ]".format(exe_file, shc_file, len(code)))


def get_code_section(pe_file):
    try:
        # Load the PE file
        pe = pefile.PE(pe_file)

        # Iterate over the sections
        for section in pe.sections:
            # Check if this is the code section
            if '.text' in section.Name.decode().rstrip('\x00'):
                data = section.get_data()
                data = remove_trailing_null_bytes(data)
                print("    > Code Size: {}  (raw code section size: {})".format(
                    len(data), section.SizeOfRawData))
                return data
        else:
            print("Code section not found.")
    
    except FileNotFoundError:
        print(f"File not found: {pe_file}")
    except pefile.PEFormatError:
        print(f"Invalid PE file: {pe_file}")


def remove_trailing_null_bytes(data):
    for i in range(len(data) - 1, -1, -1):
        if data[i] != b'\x00'[0]:  # Check for a non-null byte
            return data[:i + 1]
    return b''  # If the entire sequence is null bytes
