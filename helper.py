import subprocess
import os
import pathlib
import glob
import logging

from config import config
from model.defs import *

logger = logging.getLogger("Helper")

SHC_VERIFY_SLEEP = 0.1


def clean_files():
    logger.info("--( Remove old files")
    
    files_to_clean = [
        # compile artefacts in current dir
        "main-clean.obj",
        "main.obj",
        "mllink$.lnk",
        #"out/7z-verify.exe",
        #"out/wifiinfoview-verify.exe",
        #"out/procexp64-verify.exe",
        # out/ stuff
        os.path.join(build_dir, "main.asm"),
        os.path.join(build_dir, "main.bin"),
        os.path.join(build_dir, "main.c"),
        os.path.join(build_dir, "peb_lookup.h"),
        os.path.join(build_dir, "main.exe"),
        
        VerifyFilename,
    ]
    for file in files_to_clean:
        pathlib.Path(file).unlink(missing_ok=True)


def run_process_checkret(args, check=True):
    ret = subprocess.CompletedProcess("", 666)
    try:
        ret = subprocess.run(args, capture_output=True)
    except KeyboardInterrupt:
        logger.warn("Caught KeyboardInterrupt, exiting gracefully...")
    except subprocess.CalledProcessError as e:
        logger.warn(f"Command '{e.cmd}' returned non-zero exit status {e.returncode}.")
        # Handle the error case
    except Exception as e:
        logger.warn(f"An error occurred: {e}")
        # Handle other exceptions
    
    with open(f"{logs_dir}/cmdoutput.log", "ab") as f:
        cmd = "------------------------------------\n"
        cmd += "--- " + " ".join(args) + "\n"
        f.write(cmd.encode('utf-8'))
        if ret.stdout != None:
            f.write(ret.stdout)
        if ret.stderr != None:
            f.write(ret.stderr)
    if ret.returncode != 0 and check:
        logger.info("----! FAILED Command: {}".format(" ".join(args)))
        if ret.stdout != None:
            logger.info(ret.stdout.decode('utf-8'))
        if ret.stderr != None:
            logger.info(ret.stderr.decode('utf-8'))
        raise Exception("Command failed: " + " ".join(args))
    if config.ShowCommandOutput:
        logger.info("> " + " ".join(args))
        if ret.stdout != None:
            logger.info(ret.stdout.decode('utf-8'))
        if ret.stderr != None:
            logger.info(ret.stderr.decode('utf-8'))


def try_start_shellcode(shc_file):
    logger.info("--[ Blindly execute shellcode: {}".format(shc_file))
    subprocess.run([
        config.get["path_runshc"],
        shc_file,
    ])


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
            #logger.info(f"Deleted {file_path}")
        except Exception as e:
            logger.info(f"Error deleting {file_path}: {e}")


def rbrunmode_str(rbrunmode):
    rbrunmode = str(rbrunmode)
    if rbrunmode == "1":
        return "change address of entrypoint"
    elif rbrunmode == "2":
        return "hijack branching instruction in entrypoint"
    else:
        return "Invalid: {}".format(rbrunmode)


def hexdump(data, addr = 0, num = 0):
    s = ''
    n = 0
    lines = []
    if num == 0: num = len(data)

    if len(data) == 0:
        return '<empty>'

    for i in range(0, num, 16):
        line = ''
        line += '%04x | ' % (addr + i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x ' % (data[j] & 0xff)

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
            line += '%c' % c

        lines.append(line)
    return '\n'.join(lines)


def file_to_lf(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    data = data.replace(b'\r\n', b'\n')
    with open(filename, 'wb') as f:
        f.write(data)


def find_first_utf16_string_offset(data, min_len=8):
    current_string = bytearray()
    start_offset = None  # To keep track of the start of the current string
    for i in range(0, len(data) - 1, 2):
        # Check if we have a valid character
        if data[i] != 0 or data[i+1] != 0:
            if start_offset is None:  # Mark the start of a new string
                start_offset = i
            current_string += bytes([data[i], data[i+1]])
        else:
            if len(current_string) >= min_len * 2:  # Check if the current string meets the minimum length
                return start_offset  # Return the offset where the string starts
            current_string = bytearray()
            start_offset = None  # Reset start offset for the next string

    return None  # No string found that meets the criteria

