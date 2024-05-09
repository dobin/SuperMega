import os
import pprint
import logging
import shutil
from typing import List, Dict

from helper import *
from config import config
from observer import observer
from model import *
from phases.masmshc import masm_shc, Params
from model.carrier import Carrier
from phases.asmparser import parse_asm_file
from model.settings import Settings

logger = logging.getLogger("Compiler")


# NOTE: Mostly copy-pasted from compiler.py::compile()
def compile_dev(
    c_in: FilePath, 
    asm_out: FilePath,
    short_call_patching: bool = False,
):
    logger.info("--( Compile C to ASM: {} -> {} ".format(c_in, asm_out))

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
    
    asm_text: str = file_readall_text(asm_out)
    observer.add_text_file("carrier_asm_orig", asm_text)

    logger.info("---[ ASM masm_shc: {} ".format(asm_out))
    asm_text_lines: List[str] = parse_asm_file(Carrier(), asm_text)
    asm_text = masm_shc(asm_text_lines)
    observer.add_text_file("carrier_asm_cleanup", asm_text)

    with open(asm_out, "w") as f:
        f.write(asm_text)


def compile(
    c_in: FilePath, 
    asm_out: FilePath,
    carrier: Carrier,
    settings: Settings,
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
    asm_text = file_readall_text(asm_out)
    observer.add_text_file("carrier_asm_orig", asm_text)

    asm_text_lines = parse_asm_file(carrier, asm_text, settings) # Fixup assembly file
    asm_text = masm_shc(asm_text_lines) # Cleanup assembly file
    observer.add_text_file("carrier_asm_final", asm_text)

    # write back. Next step would be compiling this file
    with open(asm_out, "w") as f:
        f.write(asm_text)
