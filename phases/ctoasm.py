from helper import *
from config import config


def make_c_to_asm(c_file, asm_file, payload_len):
    print("--[ C to ASM: {} -> {} ]".format(c_file, asm_file))

    asm = {
        "initial": "",
        "cleanup": "",
        "fixup": "",
    }

    # Phase 1: Compile
    print("---[ Compile: {} ]".format(c_file))
    run_process_checkret([
            config.get("path_cl"),
            "/c",
            "/FA",
            "/GS-",
            "/Fa{}/".format(os.path.dirname(c_file)),
            c_file,
    ])
    if not os.path.isfile(asm_file):
        print("Error: Compiling failed")
        return
    asm["initial"] = file_readall_text(asm_file)

    # Phase 2: Assembly cleanup
    asm_clean_file = asm_file + ".clean"
    print("---[ Cleanup: {} ]".format(asm_file))
    run_process_checkret([
        config.get("path_masmshc"),
        asm_file,
        asm_clean_file,
    ])
    if not os.path.isfile(asm_clean_file):
        print("Error: Cleanup filed")
        return
    else:
        shutil.move(asm_clean_file, asm_file)
        asm["cleanup"] = file_readall_text(asm_file)

    # Phase 2: Assembly fixup
    print("---[ Fixup  : {} ]".format(asm_file))
    if not fixup_asm_file(asm_file, payload_len):
        print("Error: Fixup failed")
        return
    else:
        asm["fixup"] = file_readall_text(asm_file)

    return asm


def fixup_asm_file(filename, payload_len):
    with open(filename, 'r') as asmfile:
        lines = asmfile.readlines()

    # replace external reference with shellcode reference
    for idx, line in enumerate(lines): 
        if "dobin" in lines[idx]:
            print("    > Replace external reference at line: {}".format(idx))
            lines[idx] = lines[idx].replace(
                "mov	r8, QWORD PTR dobin",
                "lea	r8, [shcstart]"
            )

    # replace payload length
    for idx, line in enumerate(lines): 
        if "11223344" in lines[idx]:
            print("    > Replace payload length at line: {}".format(idx))
            lines[idx] = lines[idx].replace("11223344", str(payload_len+1))
            break
            
    # add label at end of code
    for idx, line in enumerate(lines): 
        if lines[idx].startswith("END"):
            print("    > Add end of code label at line: {}".format(idx))
            lines.insert(idx-1, "shcstart:\r\n")
            lines.insert(idx, "\tnop\r\n")
            break
    
    with open(filename, 'w') as asmfile:
        asmfile.writelines(lines)

    return True