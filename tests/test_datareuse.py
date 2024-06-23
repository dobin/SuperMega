import shutil
from typing import List
import unittest
import logging
import os

from model.defs import *

from pe.superpe import SuperPe
from model.rangemanager import RangeManager
from helper import *


class DataReuseTest(unittest.TestCase):
    def test_rangemanager(self):
        """Test RangeManager for basic functionality"""
        rm = RangeManager(0, 100)
        rm.add_range(0, 10)
        rm.add_range(20, 30)
        rm.add_range(50, 60)

        hole = rm.find_hole(10)
        self.assertEqual((11, 19), hole)

        holes = rm.find_holes(20)
        self.assertEqual([(31, 49), (61, 100)], holes)

        largest = rm.find_largest_gap()
        self.assertEqual(40, largest)


    def test_rangemanager_2(self):
        rm = RangeManager(0, 100)
        rm.add_range(0, 90)
        hole = rm.find_hole(5)
        self.assertIsNotNone(hole)

    def test_relocation_list(self):
        superpe = SuperPe(PATH_EXES + "7z.exe")
        relocs = superpe.get_relocations_for_section(".rdata")
        self.assertEqual(836, len(relocs))
        reloc = relocs[0]
        self.assertEqual(393216, reloc.base_rva)
        self.assertEqual(394296, reloc.rva)
        self.assertEqual(1080, reloc.offset)
        self.assertEqual("I", reloc.type)


    def test_relocmanager(self):
        """Test reference EXE reloc manager information"""
        superpe = SuperPe(PATH_EXES + "procexp64.exe")
        rm = superpe.get_rdata_relocmanager()
        self.assertEqual(61, len(rm.intervals))
        # 0x1ab0 is magic currently (should use find_first_utf16_string_offset()
        hole = rm.find_hole(20)
        self.assertEqual(hole, (1174185, 1174591))


    def test_largestgap(self):
        superpe = SuperPe(PATH_EXES + "7z.exe")
        rm = superpe.get_rdata_relocmanager()
        start, stop = rm.find_hole(100)
        self.assertEqual(394513, start)
        self.assertEqual(396511, stop)


    def test_rdata_overwrite(self):
        pass


    def test_asm_lea_create(self):
        pass

