import shutil
from typing import List
import unittest
import logging
import os

from model.exehost import ExeHost
from phases.datareuse import ReusedataAsmFileParser

class DataReuseTest(unittest.TestCase):
    def test_relocation_list(self):
        exe_host = ExeHost("data/exes/7z.exe")
        exe_host.init()

        relocs = exe_host.get_relocations_for_section(".rdata")
        self.assertEqual(30, len(relocs))
        reloc = relocs[0]
        self.assertEqual(393216, reloc.base_rva)
        self.assertEqual(394296, reloc.rva)
        self.assertEqual(1080, reloc.offset)
        self.assertEqual("I", reloc.type)


    def test_largestgap(self):
        exe_host = ExeHost("data/exes/7z.exe")
        exe_host.init()

        size, start, stop = exe_host.get_reloc_largest_gap(".rdata")
        self.assertEqual(129395, size)
        self.assertEqual(3807, start)
        self.assertEqual(133203, stop)


    def test_rdata_overwrite(self):
        pass


    def test_asm_lea_create(self):
        pass


    def test_data_reuse_entries(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        data_reuse_entries = []

        asmFileParser = ReusedataAsmFileParser(asm_in)
        asmFileParser.init()
        asmFileParser.process()
        data_reuse_entries = asmFileParser.get_reusedata_fixups()

        self.assertEqual(2, len(data_reuse_entries))

        entry = data_reuse_entries[0]
        self.assertTrue('$SG72513' in entry.string_ref)
        self.assertTrue('rcx' in entry.register)
        self.assertEqual(entry.data, b"U\x00S\x00E\x00R\x00P\x00R\x00O\x00F\x00I\x00L\x00E\x00\x00\x00")
        self.assertEqual(entry.addr, 0)
        self.assertEqual(7, len(entry.randbytes))  # needs to be 7!

        entry = data_reuse_entries[1]
        self.assertTrue('$SG72514' in entry.string_ref)


    def test_data_reuse_fixup(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        asm_out = asm_in + ".test"
        asmFileParser = ReusedataAsmFileParser(asm_in)
        asmFileParser.init()
        asmFileParser.process()
        asmFileParser.write_lines_to(asm_out + ".test")
        with open(asm_out + ".test", "r") as f:
            lines = f.readlines()
        self.assertTrue("\tDB " in lines[108-1])
        self.assertFalse("OFFSET FLAT:$SG" in lines[108-1])
        os.remove(asm_out + ".test")
