from typing import List
import unittest

from model.defs import *
from utils import hexdump
from observer import observer
from model.defs import *
from pe.derbackdoorer import FunctionBackdoorer, DEPTH_OPTIONS
from pe.superpe import SuperPe


class DerBackdoorerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        observer.active = False


    def test_function_backdoorer_exe(self):
        superpe = SuperPe(PATH_EXES + "iattest-full.exe")
        function_backdoorer = FunctionBackdoorer(superpe, depth_option=DEPTH_OPTIONS.LEVEL1)

        addr = function_backdoorer.find_suitable_instruction_addr(superpe.get_entrypoint())
        self.assertEqual(addr, 0x1304)

        trampoline_compiled, trampline_text, trampoline_reloc_offset = function_backdoorer.get_trampoline(addr, 0x11223344)
        self.assertEqual(trampoline_compiled[0], 0x48)
        self.assertEqual(trampoline_compiled[2], 0x44)
        self.assertEqual(trampoline_compiled[3], 0x33)
        self.assertEqual(trampoline_compiled[4], 0x22)
        self.assertEqual(trampoline_compiled[5], 0x51)
        self.assertEqual(trampoline_compiled[6], 0x01)
        self.assertEqual(trampoline_compiled[10], 0xff)
        self.assertEqual(trampoline_reloc_offset, 2)


    def test_function_backdoorer_dll(self):
        superpe = SuperPe(PATH_EXES + "libbz2-1.dll")
        function_backdoorer = FunctionBackdoorer(superpe)

        addr = function_backdoorer.find_suitable_instruction_addr(superpe.get_entrypoint())
        self.assertEqual(addr, 0x135D)

        trampoline_compiled, trampoline_reloc_offset = function_backdoorer.get_trampoline(addr, 0x11223344)
        self.assertEqual(trampoline_compiled[0], 0x48)
        self.assertEqual(trampoline_compiled[2], 0x44)
        self.assertEqual(trampoline_compiled[3], 0x33)
        self.assertEqual(trampoline_compiled[4], 0x22)
        self.assertEqual(trampoline_compiled[5], 0x51)
        self.assertEqual(trampoline_compiled[6], 0x01)
        self.assertEqual(trampoline_compiled[10], 0xff)
        self.assertEqual(trampoline_reloc_offset, 2)