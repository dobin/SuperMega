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
from phases.datareuse import *
from model.carrier import Carrier
from model.exehost import ExeHost

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
    source_style: SourceStyle,
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

    # DataReuse first
    asmFileParser = ReusedataAsmFileParser(asm_out)
    asmFileParser.init()
    asmFileParser.process()
    carrier.set_datareuse_fixups(asmFileParser.get_reusedata_fixups())
    asmFileParser.write_lines_to(asm_out)

    # Assembly text fixup (SuperMega)
    logger.info("---[ ASM Fixup  : {} ".format(asm_out))
    if not fixup_asm_file(asm_out, payload_len, short_call_patching=short_call_patching):
        raise Exception("Error: Fixup failed")
    
    if config.debug:
        observer.add_text_file("carrier_asm_fixup", file_readall_text(asm_out))

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

    if source_style == SourceStyle.iat_reuse:
        fixup_iat_reuse(asm_clean_file, carrier)
        observer.add_text_file("carrier_asm_updated", file_readall_text(asm_clean_file))

        if not exe_host.has_all_carrier_functions(carrier):
            logger.error("Error: Not all carrier functions are available in the target exe")
            return

    # Move to destination we expect
    shutil.move(asm_clean_file, asm_out)
    if config.debug:
        observer.add_text_file("carrier_asm_cleanup", file_readall_text(asm_out))


def bytes_to_asm_db(byte_data: bytes) -> bytes:
    # Convert each byte to a string in hexadecimal format 
    # prefixed with '0' and suffixed with 'h'
    hex_values = [f"0{byte:02x}H" for byte in byte_data]
    formatted_string = ', '.join(hex_values)
    return "\tDB " + formatted_string


def fixup_asm_file(filename: FilePath, payload_len: int, short_call_patching: bool = False):
    with open(filename, 'r') as asmfile:  # None = translate to \n
        lines = asmfile.readlines()

    # When it breaks, enable this
    if short_call_patching:
        for idx, line in enumerate(lines):
            if "jmp\tSHORT" in lines[idx]:
                lines[idx] = lines[idx].replace("SHORT", "")
        
    for idx, line in enumerate(lines):     
        # Remove EXTRN, we dont need it
        # Even tho it is part of IAT_REUSE process (see fixup_iat_reuse())
        if "EXTRN	__imp_" in lines[idx]:
            lines[idx] = "; " + lines[idx]

    # replace external reference with shellcode reference
    for idx, line in enumerate(lines): 
        if "supermega_payload" in lines[idx]:
            logger.info("    > Replace external reference at line: {}".format(idx))
            #lines[idx] = lines[idx].replace(
            #    "mov	r8, QWORD PTR supermega_payload",
            #    "lea	r8, [shcstart]"
            #)
            # better keep register (hack)
            lines[idx] = lines[idx].replace(
                "mov	",
                "lea	"
            )
            lines[idx] = lines[idx].replace(
                "QWORD PTR supermega_payload",
                "[shcstart]  ; get payload shellcode address"
            )

    # add label at end of code
    for idx, line in enumerate(lines): 
        if lines[idx].startswith("END"):
            logger.info("    > Add end of code label at line: {}".format(idx))
            lines.insert(idx-1, "shcstart:  ; start of payload shellcode\n")
            break

    with open(filename, 'w',) as asmfile:  # write back with CRLF
        #for line in lines:
        #    asmfile.write(line + "\n")
        asmfile.writelines(lines)

    return True


def get_function_stubs(asm_in: FilePath) -> List[str]:
    functions = []

    with open(asm_in, 'r', encoding='utf-8') as asmfile:
        lines = asmfile.readlines()

    # EXTRN	__imp_GetEnvironmentVariableW:PROC
    for line in lines:
        if "QWORD PTR __imp_" in line:
            a = line
            a = a.split("__imp_")[1]
            func_name = a.strip("\r\n")
            print("    > loader shellcode IAT requirement: {}".format(func_name))
            functions.append(func_name)

    return functions


def fixup_iat_reuse(filename: FilePath, carrier: Carrier):
    with open(filename, 'r', encoding='utf-8') as asmfile:
        lines = asmfile.readlines()

    # do IAT reuse
    for idx, line in enumerate(lines):
        # Fix call
        # call	QWORD PTR __imp_GetEnvironmentVariableW
        if "call" in lines[idx] and "__imp_" in lines[idx]:
            func_name = lines[idx][lines[idx].find("__imp_")+6:].rstrip()

            randbytes: bytes = os.urandom(6)
            lines[idx] = bytes_to_asm_db(randbytes) + " ; IAT Reuse for {}".format(func_name)
            lines[idx] += "\n"
            carrier.add_iat_request(func_name, randbytes)

            logger.info("    > Replace func name: {} with {}".format(
                func_name, randbytes.hex()))
    
    with open(filename, 'w') as asmfile:
        asmfile.writelines(lines)

    if config.debug:
        observer.add_text_file("carrier_asm_iat_patch", file_readall_text(filename))
