import shutil
from typing import List
import unittest
import logging

from model.exehost import ExeHost
from model.defs import *
from pe.pehelper import extract_code_from_exe_file
from utils import hexdump
from observer import observer
from model.defs import *
from pe.derbackdoorer import FunctionBackdoorer
from pe.superpe import SuperPe


class DerBackdoorerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        observer.active = False


    def test_function_backdoorer_exe(self):
        shellcode = b"\x90" * 200
        superpe = SuperPe(PATH_EXES + "iattest-full.exe")
        function_backdoorer = FunctionBackdoorer(superpe, shellcode)

        instr = function_backdoorer.find_suitable_instruction_addr(superpe.get_entrypoint(), 128, 5)
        self.assertIsNotNone(instr)
        self.assertEqual(instr.mnemonic, "jne")
        self.assertEqual(instr.address, 0x1701)


    def test_function_backdoorer_dll(self):
        shellcode = b"\x90" * 200
        superpe = SuperPe(PATH_EXES + "libbz2-1.dll")
        function_backdoorer = FunctionBackdoorer(superpe, shellcode)

        instr = function_backdoorer.find_suitable_instruction_addr(superpe.get_entrypoint(), 128, 5)
        self.assertIsNotNone(instr)
        self.assertEqual(instr.mnemonic, "jne")
        self.assertEqual(instr.address, 0x1220)
