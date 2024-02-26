import shutil
from typing import List
import unittest
import logging

from model.exehost import ExeHost
from model.defs import *
from peparser.pehelper import extract_code_from_exe_file
from helper import hexdump
from observer import observer

from derbackdoorer.derbackdoorer import PeBackdoor


# What to make sure of: 
# 1: Change of AddressEntryPoint
#   * Shellcode is at the location given
#   * EP points to the shellcode
#
# 2: Hijack
#   * Shellcode is at the location given
#   * The call has been patched

class DerBackdoorerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        observer.active = False

    def test_backdoor_ep(self):
        # Write example shellcode
        shellcode_path = "exes/shellcode.test"
        shellcode = b"\x90" * 200
        with open(shellcode_path, "wb") as f:
            f.write(shellcode)

        exe_path = "exes/iattest-full.exe"
        exe_out_path = "exes/iattest-full-test.exe"

        shutil.copyfile(exe_path, exe_out_path)

        peinj = PeBackdoor()
        result = peinj.backdoor(
            1, # always overwrite .text section
            1, # EntryPoint change
            shellcode_path, 
            exe_path,
            exe_out_path,
        )

        self.assertTrue(result)
        code = extract_code_from_exe_file(exe_out_path)
        extracted_code = code[peinj.shellcodeOffsetRel:peinj.shellcodeOffsetRel+len(shellcode)]
        self.assertEqual(shellcode, extracted_code)

        os.remove(exe_out_path)
        os.remove(shellcode_path)


    def test_backdoor_hijack(self):
        # Write example shellcode
        shellcode = b"\x90" * 200
        with open("exes/shellcode.test", "wb") as f:
            f.write(shellcode)

        shellcode_path = "exes/shellcode.test"
        exe_path = "exes/7z.exe"
        exe_out_path = "exes/7z-test.exe"

        shutil.copyfile(exe_path, exe_out_path)

        peinj = PeBackdoor()
        result = peinj.backdoor(
            1, # always overwrite .text section
            2, # Hijack
            shellcode_path, 
            exe_path,
            exe_out_path,
        )

        self.assertTrue(result)

        # code
        code = extract_code_from_exe_file(exe_out_path)
        extracted_code = code[peinj.shellcodeOffsetRel:peinj.shellcodeOffsetRel+len(shellcode)]
        self.assertEqual(shellcode, extracted_code)

        # jmp
        #  48 c7 c2 d7 fb 42 00 ff d2 5b 0f b7
        #  48 c7 c6 d7 fb 42 00 ff d6 5b 0f b7
        jmp_code = code[peinj.backdoorOffsetRel:peinj.backdoorOffsetRel+12]
        self.assertEqual(jmp_code[0], 0x48)
        self.assertEqual(jmp_code[1], 0xc7)
        #self.assertEqual(jmp_code[2], 0x??)  # variable
        self.assertEqual(jmp_code[3], 0xd7)
        self.assertEqual(jmp_code[4], 0xfb)
        self.assertEqual(jmp_code[5], 0x42)
        self.assertEqual(jmp_code[6], 0x00)
        self.assertEqual(jmp_code[7], 0xff)
        #self.assertEqual(jmp_code[8], 0x??) # variable
        self.assertEqual(jmp_code[9], 0x5b)
        self.assertEqual(jmp_code[10], 0x0f)
        self.assertEqual(jmp_code[11], 0xb7)

        os.remove(exe_out_path)