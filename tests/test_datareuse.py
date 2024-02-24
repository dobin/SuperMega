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

