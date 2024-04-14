from typing import List
import unittest
import logging

from model.defs import *
from pe.superpe import SuperPe
from model.exehost import ExeHost
from model.rangemanager import RangeManager


class RangeManagerTest(unittest.TestCase):
    def test_rangemanager(self):
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


    def test_relocmanager(self):
        exehost = ExeHost(PATH_EXES + "procexp64.exe")
        exehost.init()
        section = exehost.superpe.get_section_by_name(".rdata")
        rm = exehost.get_rdata_relocmanager()
        self.assertEqual(69, len(rm.intervals))
        # 0x1ab0 is magic currently (should use find_first_utf16_string_offset()
        #rm.add_range(section.virt_addr, section.virt_addr + 0x1AB0)
        hole = rm.find_hole(20)
        self.assertEqual(hole, (1167361, 1173015))
