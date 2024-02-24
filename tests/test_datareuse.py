import shutil
from typing import List
import unittest
import logging

from model import ExeInfo
from defs import *
from helper import hexdump
from observer import observer

from phases.datareuse import *


class DataReuseTest(unittest.TestCase):
    def test_relocation_list(self):
        data_reuser = DataReuser("exes/7z.exe")
        data_reuser.init()

        relocs = data_reuser.get_relocations_for_section(".rdata")
        self.assertEqual(30, len(relocs))
        reloc = relocs[0]
        self.assertEqual(393216, reloc.base_rva)
        self.assertEqual(394296, reloc.rva)
        self.assertEqual(1080, reloc.offset)
        self.assertEqual("I", reloc.type)


    def test_largestgap(self):
        data_reuser = DataReuser("exes/7z.exe")
        data_reuser.init()

        size, start, stop = data_reuser.get_reloc_largest_gap(".rdata")
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

        asmFileParser = AsmFileParser(asm_in)
        asmFileParser.init()
        data_reuse_entries = asmFileParser.get_data_reuse_entries()

        self.assertEqual(2, len(data_reuse_entries))
        self.assertTrue('$SG72513' in data_reuse_entries)
        self.assertTrue('$SG72514' in data_reuse_entries)

        self.assertEqual(data_reuse_entries['$SG72513'], b"U\x00S\x00E\x00R\x00P\x00R\x00O\x00F\x00I\x00L\x00E\x00\x00\x00")


    def test_data_reuse_fixup(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        asm_out = asm_in + ".test"
        asmFileParser = AsmFileParser(asm_in)
        asmFileParser.init()

        data_fixups = asmFileParser.fixup_data_reuse()
        self.assertEqual(2, len(data_fixups))
        fixup = data_fixups[0]
        self.assertTrue(fixup["string_ref"], "rcx")
        self.assertTrue(fixup["register"], "$SG72513")
        self.assertEqual(5, len(fixup["randbytes"]))

        asmFileParser.write_lines_to(asm_out)

        with open(asm_out, "r") as f:
            lines = f.readlines()
        self.assertTrue("\tDB " in lines[108-1])
        self.assertFalse("OFFSET FLAT:$SG" in lines[108-1])

