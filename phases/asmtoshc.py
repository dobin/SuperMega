import pefile
import pprint

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
