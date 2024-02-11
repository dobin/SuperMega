import subprocess
import os
import time
import shutil
import pathlib
import sys
import pefile
import glob

from config import config
from project import project
from pehelper import *

SHC_VERIFY_SLEEP = 0.1


verify_filename = r'C:\Temp\a'
build_dir = "build"


def remove_trailing_null_bytes(data):
    for i in range(len(data) - 1, -1, -1):
        if data[i] != b'\x00'[0]:  # Check for a non-null byte
            return data[:i + 1]
    return b''  # If the entire sequence is null bytes


def get_code_section_data(pe_file):
    try:
        # Load the PE file
        pe = pefile.PE(pe_file)

        # Iterate over the sections
        #for section in pe.sections:
        #    # Check if this is the code section
        #    if '.text' in section.Name.decode().rstrip('\x00'):
        #        data = section.get_data()
        #        data = remove_trailing_null_bytes(data)
        #        print("    > 0x{:X} Code Size: {}  (raw code section size: {})".format(
        #            section.VirtualAddress,
        #            len(data), section.SizeOfRawData))
        #        return data

        section = get_code_section(pe)
        if section == None:
            raise Exception("Code section not found.")
            
        print("--[ Code section: {}".format(section.Name.decode().rstrip('\x00')))
        data = section.get_data()
        data = remove_trailing_null_bytes(data)
        print("    > 0x{:X} Code Size: {}  (raw code section size: {})".format(
            section.VirtualAddress,
            len(data), section.SizeOfRawData))
        return data

    except FileNotFoundError:
        print(f"File not found: {pe_file}")
    except pefile.PEFormatError:
        print(f"Invalid PE file: {pe_file}")


def write_code_section(pe_file, new_data):
    # Load the PE file
    pe = pefile.PE(pe_file)

    # Iterate over the sections
    for section in pe.sections:
        # Check if this is the code section
        if '.text' in section.Name.decode().rstrip('\x00'):
            file_offset = section.PointerToRawData
            
            with open(pe_file, 'r+b') as f:
                f.seek(file_offset)
                f.write(new_data)
                #print("Successfully overwritten the .text section with new data.")
            break


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
        os.path.join(build_dir, "peb_lookup.h"),
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
    if project.show_command_output:
        print("> " + " ".join(args))
        print(ret.stdout)
        print(ret.stderr)

def try_start_shellcode(shc_file):
    print("--[ Blindly execute shellcode: {} ]".format(shc_file))
    subprocess.run([
        config.get["path_runshc"],
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


def delete_all_files_in_directory(directory_path):
    files = glob.glob(os.path.join(directory_path, '*'))
    for file_path in files:
        try:
            os.remove(file_path)
            #print(f"Deleted {file_path}")
        except Exception as e:
            print(f"Error deleting {file_path}: {e}")