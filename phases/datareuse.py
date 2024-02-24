import sys
import pefile
from intervaltree import Interval, IntervalTree
from typing import List
import os


class PeSection():
    def __init__(self, pefile_section):
        self.name: str = pefile_section.Name.rstrip(b'\x00').decode("utf-8")
        self.raw_addr: int = pefile_section.PointerToRawData
        self.raw_size: int = pefile_section.SizeOfRawData
        self.virt_addr: int = pefile_section.VirtualAddress
        self.virt_size: int = pefile_section.Misc_VirtualSize
        #self.permissions = pefile_section.Characteristics


class PeRelocation():
    def __init__(self, reloc):
        self.rva: int = reloc.rva
        self.base_rva: int = reloc.base_rva
        self.offset: int = reloc.rva - reloc.base_rva
        self.type: str = pefile.RELOCATION_TYPE[reloc.type][0]


def bytes_to_asm_db(byte_data: bytes) -> bytes:
    # Convert each byte to a string in hexadecimal format 
    # prefixed with '0' and suffixed with 'h'
    hex_values = [f"0{byte:02x}H" for byte in byte_data]
    formatted_string = ', '.join(hex_values)
    return "\tDB " + formatted_string


class AsmFileParser():
    def __init__(self, filepath):
        self.filepath = filepath
        self.lines = []


    def init(self):
        with open(self.filepath, "r") as f:
            self.lines = f.readlines()
        self.lines = [line.rstrip() for line in self.lines]


    def fixup_data_reuse(self):
        fixups = []
        # lea	rcx, OFFSET FLAT:$SG72513
        for idx, line in enumerate(self.lines):
            if "OFFSET FLAT:$SG" in line:
                string_ref = line.split("OFFSET FLAT:")[1]
                register = line.split("lea\t")[1].split(",")[0]
                randbytes: bytes = os.urandom(7) # lea is 7 bytes
                fixups.append({
                    "string_ref": string_ref,
                    "register": register,
                    "randbytes": randbytes,
                })
                self.lines[idx] = bytes_to_asm_db(randbytes) + " ; .rdata Reuse for {} ({})".format(
                    string_ref, register)
        return fixups


    def get_data_reuse_entries(self) -> List[str]:
        entries = {}
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
                entries[name] = value

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
                        #print("--> {}".format(line))
                        #print("---> {}".format(hex))
                        value += bytes.fromhex(hex)

                entries[current_entry_name] += value
            else:
                current_entry_name = ""
                
        return entries


    def write_lines_to(self, filename):
        with open(filename, 'w',) as asmfile:
            for line in self.lines:
                asmfile.write(line + "\n")


class DataReuser():
    def __init__(self, filepath):
        self.pe = pefile.PE(filepath)
        self.pe_sections: List[PeSection] = []
        self.base_relocs: List[PeRelocation] = []


    def init(self):
        # Sections
        for section in self.pe.sections:
            self.pe_sections.append(PeSection(section))

        # Base Relocations
        if hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    self.base_relocs.append(PeRelocation(entry))

        #self.pe.close()


    def get_section_by_name(self, name: str) -> PeSection:
        for section in self.pe_sections:
            print("{} {}".format(section.name, name))
            if section.name == name:
                return section
        return None
    
    
    def get_relocations_all(self) -> List[PeRelocation]:
        return self.base_relocs
    
    
    def get_relocations_for_section(self, section_name) -> List[PeRelocation]:
        section = self.get_section_by_name(section_name)
        if section is None:
            return []
        return [reloc for reloc in self.base_relocs if reloc.base_rva == section.virt_addr]
    

    def get_reloc_largest_gap(self, section_name=".rdata"):
        tree = IntervalTree()
        section = self.get_section_by_name(section_name)

        #print("MOTHERFUCKER: {}".format(section))
        #print("MOTHERFUCKER: {}".format(self.base_relocs))
        print("-- Relocations: {}".format(len(self.base_relocs)))
        print("-- section: 0x{:x}".format(section.virt_addr))

        for reloc in self.base_relocs:
            #print("FUCK: 0x{:x} 0x{:x}".format(reloc.base_rva, section.virt_addr))

            if reloc.base_rva == section.virt_addr:
                print("Adding reloc: {} {}".format(reloc.offset, reloc.offset + 8))
                tree.add(Interval(reloc.offset, reloc.offset + 8))
        tree.add(Interval(section.virt_size, section.virt_size + 1))

        # Initialize variables to track the largest gap and its bounds
        max_gap = 0
        gap_start = None
        gap_end = None

        # Sort intervals for sequential comparison
        sorted_intervals = sorted(tree)
        for i in range(len(sorted_intervals) - 1):
            current_end = sorted_intervals[i].end
            next_start = sorted_intervals[i + 1].begin
            gap = next_start - current_end
            if gap > max_gap:
                max_gap = gap
                gap_start = current_end  # Adjusted for the actual start of the gap
                gap_end = next_start - 1  # Adjusted for the actual end of the gap

        # Adjust for the artificial +1 in interval ends
        if gap_start is not None and gap_end is not None:
            gap_start -= 1

        return max_gap - 1, gap_start, gap_end
