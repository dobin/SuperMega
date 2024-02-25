from typing import List
import pefile


class PeSection():
    def __init__(self, pefile_section: pefile.SectionStructure):
        self.name: str = pefile_section.Name.rstrip(b'\x00').decode("utf-8")
        self.raw_addr: int = pefile_section.PointerToRawData
        self.raw_size: int = pefile_section.SizeOfRawData
        self.virt_addr: int = pefile_section.VirtualAddress
        self.virt_size: int = pefile_section.Misc_VirtualSize
        #self.permissions = pefile_section.Characteristics


class SuperPe():
    """Interact with a PE file using pefile"""

    def __init__(self, pe: pefile.PE):
        self.pe: pefile.PE = pe
        self.pe_sections: List[PeSection] = []


    def init(self):
        for section in self.pe.sections:
            self.pe_sections.append(PeSection(section))


    def get_section_by_name(self, name: str) -> PeSection:
        for section in self.pe_sections:
            if section.name == name:
                return section
        return None
    



