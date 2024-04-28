import shutil
from typing import List
import unittest
import logging
import os
from model.defs import *
from model.exehost import ExeHost
from model.carrier import Carrier
from phases.asmparser import parse_asm_file


class DataReuseTest(unittest.TestCase):
    def test_relocation_list(self):
        exe_host = ExeHost(PATH_EXES + "7z.exe")
        exe_host.init()

        relocs = exe_host.get_relocations_for_section(".rdata")
        self.assertEqual(842, len(relocs))
        reloc = relocs[0]
        self.assertEqual(393216, reloc.base_rva)
        self.assertEqual(394296, reloc.rva)
        self.assertEqual(1080, reloc.offset)
        self.assertEqual("I", reloc.type)


    def test_largestgap(self):
        exe_host = ExeHost(PATH_EXES + "7z.exe")
        exe_host.init()
        rm = exe_host.get_rdata_relocmanager()
        start, stop = rm.find_hole(100)
        self.assertEqual(393233, start)
        self.assertEqual(394295, stop)


    def test_rdata_overwrite(self):
        pass


    def test_asm_lea_create(self):
        pass


    def test_data_reuse_entries(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        asm_working = "tests/data/data_reuse_pre_fixup.asm.test"
        
        shutil.copy(asm_in, asm_working)
        carrier = Carrier()
        parse_asm_file(carrier, asm_working)
        data_reuse_entries = carrier.get_all_reusedata_fixups()

        self.assertEqual(2, len(data_reuse_entries))

        entry = data_reuse_entries[0]
        self.assertTrue('$SG72513' in entry.string_ref)
        self.assertTrue('rcx' in entry.register)
        self.assertEqual(entry.data, b"U\x00S\x00E\x00R\x00P\x00R\x00O\x00F\x00I\x00L\x00E\x00\x00\x00")
        self.assertEqual(entry.addr, 0)
        self.assertEqual(7, len(entry.randbytes))  # needs to be 7!

        entry = data_reuse_entries[1]
        self.assertTrue('$SG72514' in entry.string_ref)

        os.remove(asm_working)


    def test_data_reuse_fixup(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        asm_working = asm_in + ".test"
        
        shutil.copy(asm_in, asm_working)
        carrier = Carrier()
        parse_asm_file(carrier, asm_working)

        with open(asm_working, "r") as f:
            lines = f.readlines()
        self.assertTrue("\tDB " in lines[108-1])
        self.assertFalse("OFFSET FLAT:$SG" in lines[108-1])
        
        os.remove(asm_working)
