import subprocess
import os
import time
import shutil
import pathlib
import sys


SHC_VERIFY_SLEEP = 0.1

path_cl = r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\cl.exe'
path_ml64 =  r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.37.32822\bin\Hostx64\x64\ml64.exe'

path_masmshc =  r'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\masm_shc\masm_shc.exe'
path_runshc = r'C:\Users\hacker\Source\Repos\masm_shc\out\build\x64-Debug\runshc\runshc.exe'
#path_shexec = r'C:\Research\hasherezade\exec_fiber\sh-exec-fiber.exe'

verify_filename = r'C:\Temp\a'
build_dir = "build"


def clean_files():
    print("--[ Remove old files ]")
    
    files_to_clean = [
        # compile artefacts in current dir
        "main-clean.obj",
        "main.obj",
        "mllink$.lnk",

        # out/ stuff
        os.path.join(build_dir, "main.asm"),
        os.path.join(build_dir, "main.bin"),
        os.path.join(build_dir, "main.c"),
        #os.path.join(build_dir, "main.exe"),
        
        verify_filename,
    ]
    for file in files_to_clean:
        pathlib.Path(file).unlink(missing_ok=True)


def run_process_checkret(args):
    ret = None
    ret = subprocess.run(args, capture_output=True, text=True)
    if ret.returncode != 0:
        print("----! FAILED Command: {}".format(" ".join(args)))
        print(ret.stdout)
        print(ret.stderr)
        raise Exception("Command failed")


def try_start_shellcode(shc_file):
    print("--[ Blindly execute shellcode: {} ]".format(shc_file))
    subprocess.run([
        path_runshc,
        shc_file,
    ]) # , check=True


def file_readall_text(filepath) -> str:
    with open(filepath, "r") as f:
        data = f.read()
    return data


def file_readall_binary(filepath) -> bytes:
    with open(filepath, "rb") as f:
        data = f.read()
    return data
