import json
import pprint
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from typing import List, Dict

from pe.r2helper import r2_disas
from utils import delete_all_files_in_directory
from model.defs import *


class Observer():
    """Central class to store all logs and files created during the build process"""

    def __init__(self):
        self.cmd_output = []        # output of external programs (cmdoutput.log)
        self.logs: List[str] = []   # internal log messages (supermega.log)
        self.files = []             # content of generated files 
        self.active = True


    def reset(self):
        self.cmd_output = []
        self.logs = []
        self.idx = 0


    def add_cmd_output(self, cmd_output):
        self.cmd_output.append(cmd_output)


    def get_cmd_output(self):
        return self.cmd_output


    def add_log(self, log: str):
        self.logs.append(log)


    def get_logs(self):
        return self.logs


    def add_text_file(self, name, data):
        self.files.append((name + ".txt", data))


    def add_code_file(self, name, data: bytes):
        ret = r2_disas(data)
        self.files.append((name + ".disas.ascii", ret['color']))
        #self.write_to_file(name + ".disas.txt", ret['text'])
        #self.write_to_file(name + ".disas.ascii", ret['color'])
        #self.write_to_file(name + ".hex", ret['hexdump'])
        #self.write_to_file_bin(name + ".bin", data)
        #self.idx += 1

  
    #def write_to_file(self, filename, data):
    #    if not self.active:
    #        return
    #    with open("{}/{}-{}".format(logs_dir, self.idx, filename), "w") as f:
    #        f.write(data)


    #def write_to_file_bin(self, filename, data):
    #    if not self.active:
    #        return
    #    with open("{}/{}-{}".format(logs_dir, self.idx, filename), "wb") as f:
    #        f.write(data)


    #def clean_files(self):
    #    delete_all_files_in_directory(f"{logs_dir}/")
    #    self.idx = 0
    #    self.logs = []


    #def __str__(self):
    #    s = "<todo>"
    #    return s


observer = Observer()