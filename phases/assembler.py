import logging

from model import *
from config import config
from observer import observer
from pehelper import *

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
    observer.add_code("generate_shc_from_asm", code) 
    with open(shellcode_out, 'wb') as f:
        f.write(code)


def merge_loader_payload(shellcode_in: FilePath, shellcode_out: FilePath, payload: FilePath, decoder_style: DecoderStyle):
    logger.info("--[ Merge stager: {} + {} -> {}".format(
        shellcode_in, project.payload, shellcode_out))
    with open(shellcode_in, 'rb') as input1:
        data_stager = input1.read()
    with open(project.payload, 'rb') as input2:
        data_payload = input2.read()

    if project.decoder_style == DecoderStyle.PLAIN_1:
        # Nothing to do
        pass
    elif project.decoder_style == DecoderStyle.XOR_1:
        xor_key = 0x42
        logger.info("---[ XOR payload with key 0x{:x}".format(xor_key))
        data_payload = bytes([byte ^ xor_key for byte in data_payload])

    logger.info("---[ Size: Stager: {} and Payload: {}  Sum: {} ".format(
        len(data_stager), len(data_payload), len(data_stager)+len(data_payload)))

    with open(shellcode_out, 'wb') as output:
        data = data_stager + data_payload
        output.write(data)
        observer.add_code("final_shellcode", data) 
