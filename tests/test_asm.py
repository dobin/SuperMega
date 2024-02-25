import shutil
from typing import List
import unittest
import logging

from phases.compiler import fixup_asm_file, fixup_iat_reuse
from model.exehost import ExeHost
from model.defs import *
from observer import observer


class AsmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        observer.active = False
        
    def test_asm_fixup(self):
        path_in: FilePath = "tests/data/peb_walk_pre_fixup.asm"
        path_working: FilePath = "tests/data/peb_walk_pre_fixup.asm.test"

        shutil.copy(path_in, path_working)
        fixup_asm_file(path_working, 272)
        with open(path_working, "r") as f:
            lines = f.readlines()

        # cmp     DWORD PTR n$1[rsp], 11223344            ; 00ab4130H
        # cmp     DWORD PTR n$1[rsp], 272         ; 00ab4130H
        #self.assertTrue(", 272" in lines[192-1])
        #self.assertTrue("11223344" not in lines[192-1])
        
        # mov     r8, QWORD PTR supermega_payload
        # lea	r8, [shcstart]
        self.assertTrue("lea	r8, [shcstart]" in lines[198-1])
        self.assertTrue("supermega_payload" not in lines[198-1])

        # shcstart:
        self.assertTrue("shcstart:" in lines[213-1])

        os.remove(path_working)


    def test_asm_iat_fixup(self):
        path_in: FilePath = "tests/data/iat_reuse_pre_fixup.asm"
        path_working: FilePath = "tests/data/iat_reuse_pre_fixup.asm.test"
        shutil.copy(path_in, path_working)

        exe_host = ExeHost()

        fixup_iat_reuse(path_working, exe_host)
        self.assertTrue(len(exe_host.iat_resolves), 2)

        self.assertTrue("GetEnvironmentVariableW" in exe_host.iat_resolves)
        self.assertEqual(exe_host.iat_resolves["GetEnvironmentVariableW"].name, "GetEnvironmentVariableW")
        self.assertEqual(exe_host.iat_resolves["GetEnvironmentVariableW"].addr, 0)
        self.assertTrue(len(exe_host.iat_resolves["GetEnvironmentVariableW"].id), 6) # 6 random bytes

        with open(path_working, "r") as f:
            lines = f.readlines()
        
        # added ; at the beginning
        #self.assertTrue(lines[13-1].startswith("; EXTRN	__imp_GetEnvironmentVariableW:PROC"))
        #self.assertTrue(lines[14-1].startswith("; EXTRN	__imp_VirtualAlloc:PROC"))

        # 	call	QWORD PTR __imp_GetEnvironmentVariableW
        # 	DB 044H, 0aeH, 06cH, 0b6H, 072H, 07cH
        self.assertTrue(lines[158-1].startswith("	DB "))

        # 	call	QWORD PTR __imp_VirtualAlloc
        # 	DB 0c7H, 0b6H, 0feH, 0dcH, 0b2H, 0c6H
        self.assertTrue(lines[182-1].startswith("	DB "))

        os.remove(path_working)