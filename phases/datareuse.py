import sys
import pefile
from intervaltree import Interval, IntervalTree
from typing import List


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

        for reloc in self.base_relocs:
            if reloc.base_rva == section.virt_addr:
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
