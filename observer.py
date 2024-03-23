import json
import pprint
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from model import *
from pe.r2helper import r2_disas
from helper import delete_all_files_in_directory
from model.defs import *


class Observer():
    def __init__(self):
        self.logs = []
        self.idx = 0
        self.active = True

    def reset(self):
        self.logs = []
        self.idx = 0

    def add_text(self, name, data):
        self.write_to_file(name + ".txt", data)
        self.idx += 1

    def add_code(self, name, data: bytes):
        ret = r2_disas(data)
        self.write_to_file(name + ".disas.txt", ret['text'])
        self.write_to_file(name + ".disas.ascii", ret['color'])
        self.write_to_file(name + ".hex", ret['hexdump'])
        self.write_to_file_bin(name + ".bin", data)
        self.idx += 1

    def add_json(self, name, data):
        self.write_to_file(name, pprint.pformat(data, indent=4))
        self.idx += 1

    def write_to_file(self, filename, data):
        if not self.active:
            return
        with open("{}/{}-{}".format(logs_dir, self.idx, filename), "w") as f:
            f.write(data)
    def write_to_file_bin(self, filename, data):
        if not self.active:
            return
        with open("{}/{}-{}".format(logs_dir, self.idx, filename), "wb") as f:
            f.write(data)

    def clean_files(self):
        delete_all_files_in_directory(f"{logs_dir}/")
        self.idx = 0
        self.logs = []


    def __str__(self):
        s = "<todo>"
        return s


observer = Observer()