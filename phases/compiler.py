import os
import pprint
import logging
import shutil

from helper import *
from config import config
from observer import observer
from project import project
from model import *

logger = logging.getLogger("Compiler")
use_templates = True


def make_c_to_asm(c_file, asm_file, payload_len, capabilities: ExeCapabilities):
    logger.info("--[ C to ASM: {} -> {} ".format(c_file, asm_file))

    asm = {
        "initial": "",
        "templated": "",
        "cleanup": "",
        "fixup": "",
    }

    # Phase 1: C To Assembly
    logger.info("---[ Make ASM from C: {} ".format(c_file))
    run_process_checkret([
            config.get("path_cl"),
            "/c",
            "/FA",
            "/GS-",
            "/Fa{}/".format(os.path.dirname(c_file)),
            c_file,
    ])
    if not os.path.isfile(asm_file):
        logger.error("Error: Compiling failed")
        return
    asm["initial"] = file_readall_text(asm_file)

    # Phase 1.2: Assembly fixup
    logger.info("---[ Fixup  : {} ".format(asm_file))
    if not fixup_asm_file(asm_file, payload_len, capabilities):
        logger.error("Error: Fixup failed")
        return
    else:
        asm["fixup"] = file_readall_text(asm_file)

    # Phase 1.1: Assembly cleanup
    asm_clean_file = asm_file + ".clean"
    logger.info("---[ Cleanup: {} ".format(asm_file))
    run_process_checkret([
        config.get("path_masmshc"),
        asm_file,
        asm_clean_file,
    ])
    if not os.path.isfile(asm_clean_file):
        logger.info("Error: Cleanup filed")
        return
    else:
        shutil.move(asm_clean_file, asm_file)
        asm["cleanup"] = file_readall_text(asm_file)

    return asm


def bytes_to_asm_db(byte_data):
    # Convert each byte to a string in hexadecimal format 
    # prefixed with '0' and suffixed with 'h'
    hex_values = [f"0{byte:02x}H" for byte in byte_data]
    formatted_string = ', '.join(hex_values)
    return "\tDB " + formatted_string


def fixup_asm_file(filename, payload_len, capabilities: ExeCapabilities):
    with open(filename, 'r', encoding='utf-8') as asmfile:
        lines = asmfile.readlines()

    # When it breaks, enable this
    #for idx, line in enumerate(lines):
    #    if "jmp\tSHORT" in lines[idx]:
    #        lines[idx] = lines[idx].replace("SHORT", "")

    # do IAT reuse
    for idx, line in enumerate(lines):
        # Remove EXTRN, we dont need it
        if "EXTRN	__imp_" in lines[idx]:
            lines[idx] = "; " + lines[idx]
            continue

        # Fix call
        if "call" in lines[idx] and "__imp_" in lines[idx]:
            func_name = lines[idx][lines[idx].find("__imp_")+6:].rstrip()
            exeCapability = capabilities.get(func_name)
            if exeCapability == None:
                logger.error("Error Capabilities not: {}".format(func_name))
            else:
                randbytes: bytes = os.urandom(6)
                lines[idx] = bytes_to_asm_db(randbytes) + "\r\n"
                exeCapability.id = randbytes

                logger.info("    > Replace func name: {} with {}".format(
                    func_name, randbytes))
        
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
                "[shcstart]"
            )

    # replace payload length
    for idx, line in enumerate(lines): 
        if "11223344" in lines[idx]:
            logger.info("    > Replace payload length at line: {}".format(idx))
            lines[idx] = lines[idx].replace("11223344", str(payload_len))
            break
            
    # add label at end of code
    for idx, line in enumerate(lines): 
        if lines[idx].startswith("END"):
            logger.info("    > Add end of code label at line: {}".format(idx))
            lines.insert(idx-1, "shcstart:\r\n")
            break
    
    with open(filename, 'w') as asmfile:
        asmfile.writelines(lines)

    return True