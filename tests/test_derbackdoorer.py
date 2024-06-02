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


    def test_function_backdoorer_dll(self):
        superpe = SuperPe(PATH_EXES + "libbz2-1.dll")
        function_backdoorer = FunctionBackdoorer(superpe)

        addr = function_backdoorer.find_suitable_instruction_addr(superpe.get_entrypoint())
        self.assertEqual(addr, 0x135D)
