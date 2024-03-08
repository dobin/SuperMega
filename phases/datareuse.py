import sys
import pefile
from intervaltree import Interval, IntervalTree
from typing import List, Dict
import os

from model.carrier import DataReuseEntry


def bytes_to_asm_db(byte_data: bytes) -> bytes:
    # Convert each byte to a string in hexadecimal format 
    # prefixed with '0' and suffixed with 'h'
    hex_values = [f"0{byte:02x}H" for byte in byte_data]
    formatted_string = ', '.join(hex_values)
    return "\tDB " + formatted_string


class ReusedataAsmFileParser():
    def __init__(self, filepath):
        self.filepath = filepath
        self.lines = []
        self.fixups: Dict[str, DataReuseEntry] = {}


    def get_reusedata_fixups(self) -> List[DataReuseEntry]:
        return list(self.fixups.values())


    def init(self):
        with open(self.filepath, "r") as f:
            self.lines = f.readlines()
        self.lines = [line.rstrip() for line in self.lines]


    def process(self):
        self.fixup_data_reuse_code()
        self.fixup_data_reuse_data()


    def fixup_data_reuse_code(self):
        fixups = []
        # lea	rcx, OFFSET FLAT:$SG72513
        for idx, line in enumerate(self.lines):
            if "OFFSET FLAT:$SG" in line:
                string_ref = line.split("OFFSET FLAT:")[1]
                register = line.split("lea\t")[1].split(",")[0]
                randbytes: bytes = os.urandom(7) # lea is 7 bytes
                self.fixups[string_ref] = DataReuseEntry(string_ref, register, randbytes)
                self.lines[idx] = bytes_to_asm_db(randbytes) + " ; .rdata Reuse for {} ({})".format(
                    string_ref, register)
        return fixups


    def fixup_data_reuse_data(self) -> List[str]:
        current_entry_name = ""

        for line in self.lines:
            # $SG72513 DB	'U', 00H, 'S', 00H, 'E', 00H, 'R', 00H, 'P', 00H, 'R', 00H
            #          DB	'O', 00H, 'F', 00H, 'I', 00H, 'L', 00H, 'E', 00H, 00H, 00H
            if line.startswith("$SG"):
                parts = line.split()            
                name = parts[0]
                current_entry_name = name
                value = b''
                for part in parts:
                    if part.startswith('\''):
                        value += str.encode(part.split('\'')[1])
                    elif part.endswith('H') or part.endswith('H,'):
                        hex = part.split('H')[0]
                        value += bytes.fromhex(hex)

                if not name in self.fixups:
                    raise Exception("DataReuse: Entry {} not found in fixups".format(name))
                self.fixups[name].data = value
                

            elif line.startswith("\tDB"):
                if current_entry_name == "":
                    continue
                value = b''
                parts = line.split()            
                for part in parts:
                    if part.startswith('\''):
                        value += str.encode(part.split('\'')[1])
                    elif part.endswith('H') or part.endswith('H,'):
                        hex = part.split('H')[0]
                        if len(hex) == 3:
                            hex = hex.lstrip('0')
                        value += bytes.fromhex(hex)

                if not name in self.fixups:
                    raise Exception("DataReuse: Entry {} not found in fixups".format(name))
                self.fixups[name].data += value

            else:
                current_entry_name = ""
                

    def write_lines_to(self, filename):
        with open(filename, 'w',) as asmfile:
            for line in self.lines:
                asmfile.write(line + "\n")

