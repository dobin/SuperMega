import os
import pprint
import logging
import shutil
from typing import List, Dict

from helper import *
from config import config
from observer import observer
from model import *
from phases.masmshc import process_file, Params
from model.carrier import Carrier
from model.exehost import ExeHost
from phases.asmparser import parse_asm_file

logger = logging.getLogger("Compiler")


# NOTE: Mostly copy-pasted from compiler.py::compile()
def compile_dev(
    c_in: FilePath, 
    asm_out: FilePath,
    short_call_patching: bool = False,
):
    logger.info("--[ Compile C to ASM: {} -> {} ".format(c_in, asm_out))

    # Compile C To Assembly (text)
    run_process_checkret([
            config.get("path_cl"),
            "/c",
            "/FA",
            "/GS-",
            "/Fa{}/".format(os.path.dirname(c_in)),
            c_in,
    ])
    if not os.path.isfile(asm_out):
        raise Exception("Error: Compiling failed")
    file_to_lf(asm_out)
    observer.add_text_file("carrier_asm_orig", file_readall_text(asm_out))

    # Assembly cleanup (masm_shc)
    asm_clean_file = asm_out + ".clean"
    logger.info("---[ ASM masm_shc: {} ".format(asm_out))
    params = Params(asm_out, asm_clean_file, 
        inline_strings=False,  # not for DATA_REUSE
        remove_crt=True, 
        append_rsp_stub=True)  # required atm
    process_file(params)

    if not os.path.isfile(asm_clean_file):
        raise Exception("Error: Cleaned up ASM file {} was not created".format(
            asm_clean_file
        ))
    
    # Move to destination we expect
    shutil.move(asm_clean_file, asm_out)
    if config.debug:
        observer.add_text_file("carrier_asm_cleanup", file_readall_text(asm_out))


def compile(
    c_in: FilePath, 
    asm_out: FilePath,
    payload_len: int,
    carrier: Carrier,
    source_style: FunctionInvokeStyle,
    exe_host: ExeHost,
    short_call_patching: bool = False,
):
    logger.info("--[ Compile C to ASM: {} -> {} ".format(c_in, asm_out))

    # Compile C To Assembly (text)
    run_process_checkret([
            config.get("path_cl"),
            "/c",
            "/FA",
            "/GS-",
            "/Fa{}/".format(os.path.dirname(c_in)),
            c_in,
    ])
    if not os.path.isfile(asm_out):
        raise Exception("Error: Compiling failed")
    file_to_lf(asm_out)
    observer.add_text_file("carrier_asm_orig", file_readall_text(asm_out))

    # Fixup assembly file
    parse_asm_file(carrier, asm_out)

    # Cleanup assembly file
    asm_clean_file = asm_out + ".clean"
    logger.info("---[ ASM masm_shc: {} ".format(asm_out))
    params = Params(asm_out, asm_clean_file, 
        inline_strings=False,  # not for DATA_REUSE
        remove_crt=True, 
        append_rsp_stub=True)  # required atm
    process_file(params)
    if not os.path.isfile(asm_clean_file):
        raise Exception("Error: Cleaned up ASM file {} was not created".format(
            asm_clean_file
        ))
    # Move to destination we expect
    shutil.move(asm_clean_file, asm_out)

    # Log result
    observer.add_text_file("carrier_asm_cleanup", file_readall_text(asm_out))
