from typing import List, Dict
import unittest
import pefile

from pe.superpe import SuperPe, PeSection
from model.defs import *


class SuperPeTest(unittest.TestCase):

    def test_exe(self):
        dll_filepath = PATH_EXES + "procexp64.exe"
        superpe = SuperPe(dll_filepath)

        # Properties
        self.assertFalse(superpe.is_dll())
        self.assertTrue(superpe.is_64())
        self.assertFalse(superpe.is_dotnet())
        self.assertEqual(superpe.get_entrypoint(), 0xE1D78)
        self.assertIsNone(superpe.get_rwx_section())

        self.assertEqual(superpe.get_image_base(), 0x140000000)
        self.assertEqual(superpe.is_dynamic_base(), True)

        # Text Section 1 (pefile SectionStructure)
        code_sect: pefile.SectionStructure = superpe.get_code_section()
        self.assertEqual(code_sect.Name.decode(), ".text\x00\x00\x00")
        self.assertEqual(code_sect.VirtualAddress, 0x1000)
        self.assertEqual(code_sect.Misc_VirtualSize, 0x11B0CE)

        # Text Section 2 (PeSection)
        code_pesect: PeSection = superpe.get_section_by_name(".text")
        self.assertEqual(code_pesect.name, ".text")
        self.assertEqual(code_pesect.virt_addr, 0x1000)
        self.assertEqual(code_pesect.virt_size, 0x11B0CE)

        # Relocations
        base_relocs: List[PeRelocEntry] = superpe.get_base_relocs()
        self.assertEqual(len(base_relocs), 2888)
        base_reloc = base_relocs[0]
        self.assertEqual(base_reloc.rva, 0x11E618)
        self.assertEqual(base_reloc.base_rva, 0x11E000)
        self.assertEqual(base_reloc.offset, 0x618)

        # IAT
        iat_entries: Dict[str, IatEntry] = superpe.get_iat_entries()
        self.assertEqual(len(iat_entries), 24)
        self.assertTrue("kernel32.dll" in iat_entries)
        self.assertTrue("uxtheme.dll" in iat_entries)
        kernel32_entries = iat_entries["kernel32.dll"]
        self.assertEqual(len(kernel32_entries), 218)
        entry = kernel32_entries[0]
        self.assertEqual(entry.dll_name, "kernel32.dll")
        self.assertEqual(entry.func_name, "FileTimeToLocalFileTime")
        self.assertEqual(entry.iat_vaddr, 0x14011D528)

        self.assertEqual(superpe.get_vaddr_of_iatentry("FileTimeToLocalFileTime"), 0x14011D528)
        self.assertEqual(superpe.get_replacement_iat_for(
            "kernel32.dll", "GetEnvironmentStringsW"), "FileTimeToLocalFileTime")

        # Exports
        exports = superpe.get_exports_full()
        self.assertEqual(len(exports), 0)

        # VRA/Virt to Phys/Raw
        #raw = superpe.get_offset_from_rva(0xD690)
        #self.assertEqual(raw, 0xCA90)


    def test_dll(self):
        dll_filepath = PATH_EXES + "libbz2-1.dll"
        superpe = SuperPe(dll_filepath)

        # Properties
        self.assertTrue(superpe.is_dll())
        self.assertTrue(superpe.is_64())
        self.assertFalse(superpe.is_dotnet())
        self.assertEqual(superpe.get_entrypoint(), 0x1350)
        self.assertIsNone(superpe.get_rwx_section())

        self.assertEqual(superpe.get_image_base(), 0x1F13C0000)
        self.assertEqual(superpe.is_dynamic_base(), True)

        # Text Section 1 (pefile SectionStructure)
        code_sect: pefile.SectionStructure = superpe.get_code_section()
        self.assertEqual(code_sect.Name.decode(), ".text\x00\x00\x00")
        self.assertEqual(code_sect.VirtualAddress, 0x1000)
        self.assertEqual(code_sect.Misc_VirtualSize, 0x12D08)

        # Text Section 2 (PeSection)
        code_pesect: PeSection = superpe.get_section_by_name(".text")
        self.assertEqual(code_pesect.name, ".text")
        self.assertEqual(code_pesect.virt_addr, 0x1000)
        self.assertEqual(code_pesect.virt_size, 0x12D08)

        # Relocations
        base_relocs: List[PeRelocEntry] = superpe.get_base_relocs()
        self.assertEqual(len(base_relocs), 54)
        base_reloc = base_relocs[0]
        self.assertEqual(base_reloc.rva, 0x13CE8)
        self.assertEqual(base_reloc.base_rva, 0x13000)
        self.assertEqual(base_reloc.offset, 0xCE8)

        # IAT
        iat_entries: Dict[str, IatEntry] = superpe.get_iat_entries()
        self.assertEqual(len(iat_entries), 2)
        self.assertTrue("kernel32.dll" in iat_entries)
        self.assertTrue("msvcrt.dll" in iat_entries)
        kernel32_entries = iat_entries["kernel32.dll"]
        self.assertEqual(len(kernel32_entries), 12)
        entry = kernel32_entries[0]
        self.assertEqual(entry.dll_name, "kernel32.dll")
        self.assertEqual(entry.func_name, "DeleteCriticalSection")
        self.assertEqual(entry.iat_vaddr, 0x1f13db1c4)

        self.assertEqual(superpe.get_vaddr_of_iatentry("DeleteCriticalSection"), 0x1F13DB1C4)
        self.assertEqual(superpe.get_replacement_iat_for(
            "kernel32.dll", "GetEnvironmentStringsW"), "InitializeCriticalSection")

        # Exports
        exports = superpe.get_exports_full()
        self.assertEqual(len(exports), 35)
        export = exports[0]
        self.assertEqual(export["name"], "BZ2_blockSort")
        self.assertEqual(export["addr"], 0x2FC0)
        self.assertEqual(export["size"], 416)

        # VRA/Virt to Phys/Raw
        raw = superpe.get_offset_from_rva(0xD690)  # BZ2_bzdopen export
        self.assertEqual(raw, 0xCA90)
