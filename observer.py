import json
import pprint
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from model import *


class Observer():
    def __init__(self):
        self.logs = []
        self.idx = 0

    def add_text(self, name, data):
        self.write_to_file(name, data)

    def add_code(self, name, data):
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        # Disassemble the shellcode
        ret = ""
        for i in md.disasm(data, 0x0):
            ret += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)
        self.write_to_file(name, ret)

    def add_json(self, name, data):
        self.write_to_file(name, pprint.pformat(data, indent=4))

    def write_to_file(self, filename, data):
        with open("logs/{}-{}.txt".format(self.idx, filename), "w") as f:
            f.write(data)
        self.idx += 1

    def __str__(self):
        s = ""
        s += "{} {}\n\n".format(
            self.capabilities_a,
            self.options,)

        s += "Main: {} Payload Orig: {} Payload Cleanup: {}\n".format(
            len(self.main_c),
            len(self.payload_asm_orig),
            len(self.payload_asm_cleanup),

        )
        s += "fixup: {} loader: {} final: {}\n".format(
            len(self.payload_asm_fixup),
            len(self.loader_shellcode),
            len(self.final_shellcode),
        )
    
        return s


observer = Observer()