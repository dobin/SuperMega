import logging

from model import *
from config import config
from observer import observer
from pehelper import *
from helper import *

logger = logging.getLogger("Assembler")


def asm_to_shellcode(asm_in: FilePath, build_exe: FilePath, shellcode_out: FilePath):
    """Takes ASM source file asm_in, compiles it into build_exe, extracts its code section and write into shellcode_out"""
    logger.info("--[ Assemble to exe: {} -> {} -> {}".format(asm_in, build_exe, shellcode_out))
    run_process_checkret([
        config.get("path_ml64"),
        asm_in,
        "/link",
        "/OUT:{}".format(build_exe),
        "/entry:AlignRSP"
    ])
    if not os.path.isfile(build_exe):
        raise Exception("Compiling failed")
    code = extract_code_from_exe(build_exe)
    observer.add_code("carrier_shc", code) 
    with open(shellcode_out, 'wb') as f:
        f.write(code)


def merge_loader_payload(
        shellcode_in: FilePath, 
        shellcode_out: FilePath, 
        payload_data: bytes, 
        decoder_style: DecoderStyle
):
    logger.info("--[ Merge stager with payload -> {}".format(
        shellcode_out))
    
    with open(shellcode_in, 'rb') as input1:
        data_stager = input1.read()

    if decoder_style == DecoderStyle.PLAIN_1:
        # Nothing to do
        pass
    elif decoder_style == DecoderStyle.XOR_1:
        xor_key = 0x42
        logger.info("---[ XOR payload with key 0x{:x}".format(xor_key))
        payload_data = bytes([byte ^ xor_key for byte in payload_data])

    logger.info("---[ Size: Stager: {} and Payload: {}  Sum: {} ".format(
        len(data_stager), len(payload_data), len(data_stager)+len(payload_data)))

    with open(shellcode_out, 'wb') as output:
        # append them
        data = data_stager + payload_data
        output.write(data)
        observer.add_code("loader_shc", data) 
