import subprocess
import os
import pathlib
import glob
import logging
import shutil

from config import config
from model.defs import *

logger = logging.getLogger("Utils")


def check_deps():
    cl = config.get("path_cl")
    if shutil.which(cl) == None:
        logger.error("Missing dependency: " + cl)
        logger.error("Start in x64 Native Tools Command Prompt for VS 2022")
        exit(1)

    ml = config.get("path_ml64")
    if shutil.which(ml) == None:
        logger.error("Missing dependency: " + ml)
        logger.error("Start in x64 Native Tools Command Prompt for VS 2022")
        exit(1)


def delete_all_files_in_directory(directory_path):
    files = glob.glob(os.path.join(directory_path, '*'))
    for file_path in files:
        try:
            os.remove(file_path)
            #logger.info(f"Deleted {file_path}")
        except Exception as e:
            logger.info(f"Error deleting {file_path}: {e}")


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
