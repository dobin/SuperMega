from typing import List
import unittest
import logging

from model.defs import *
from model.injectable import Injectable, DataReuseEntry
from observer import observer
from helper import *
from phases.asmtextparser import parse_asm_text_file
from phases.masmshc import masm_shc
from model.settings import Settings


def print_lines(data):
    for i, line in enumerate(data):
        print(f"{i+1:3}: {line}")


class AsmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        observer.active = False

        
    def test_asm_fixup(self):
        asm_in: FilePath = "tests/data/peb_walk_pre_fixup.asm"
        asm_text = file_readall_text(asm_in)
        injectable = Injectable("fake.exe")
        injectable.add_datareuse_fixup(DataReuseEntry("supermega_payload"))
        settings: Settings = Settings()
        settings.payload_location = PayloadLocation.DATA
        asm_text_lines = parse_asm_text_file(injectable, asm_text, settings)

        # cmp     DWORD PTR n$1[rsp], 11223344            ; 00ab4130H
        # cmp     DWORD PTR n$1[rsp], 272         ; 00ab4130H
        #self.assertTrue(", 272" in lines[192-1])
        #self.assertTrue("11223344" not in lines[192-1])
        
        # Original:
        #   mov     r8, QWORD PTR supermega_payload
        # New:
        #   lea     r8, [shcstart]
        #self.assertTrue("lea	r8, [shcstart]" in asm_text_lines[198-1-1])
        self.assertTrue("DB 0" in asm_text_lines[198-1-1])


    def test_asm_iat_request(self):
        asm_in: FilePath = "tests/data/iat_reuse_pre_fixup.asm"
        asm_text = file_readall_text(asm_in)
        injectable = Injectable("fake.exe")
        injectable.add_datareuse_fixup(DataReuseEntry("supermega_payload"))
        settings: Settings = Settings()
        settings.payload_location = PayloadLocation.DATA
        asm_text_lines = parse_asm_text_file(injectable, asm_text, settings)

        self.assertEqual(len(injectable.iat_requests), 2)

        req1 = injectable.iat_requests[0]
        self.assertEqual(req1.name, "GetEnvironmentVariableW")
        self.assertTrue(len(req1.references[0]), 6) # 6 random bytes
        
        req2 = injectable.iat_requests[1]
        self.assertEqual(req2.name, "VirtualAlloc")
        self.assertTrue(len(req2.references[0]), 6) # 6 random bytes

        # added ; at the beginning
        #self.assertTrue(lines[13-1].startswith("; EXTRN	__imp_GetEnvironmentVariableW:PROC"))
        #self.assertTrue(lines[14-1].startswith("; EXTRN	__imp_VirtualAlloc:PROC"))

        # 	call	QWORD PTR __imp_GetEnvironmentVariableW
        # 	DB 044H, 0aeH, 06cH, 0b6H, 072H, 07cH
        self.assertTrue(asm_text_lines[124-1-1].startswith("	DB "))

        # 	call	QWORD PTR __imp_VirtualAlloc
        # 	DB 0c7H, 0b6H, 0feH, 0dcH, 0b2H, 0c6H
        self.assertTrue(asm_text_lines[148-1-1].startswith("	DB "))


    def test_data_reuse_entries(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        asm_text = file_readall_text(asm_in)
        injectable = Injectable("fake.exe")
        injectable.add_datareuse_fixup(DataReuseEntry("supermega_payload"))
        settings: Settings = Settings()
        settings.payload_location = PayloadLocation.DATA
        asm_text_lines = parse_asm_text_file(injectable, asm_text, settings)
        asm_text = masm_shc(asm_text_lines)  # optional here

        data_reuse_entries = injectable.get_all_reusedata_fixups()
        self.assertEqual(2+1, len(data_reuse_entries))

        entry = data_reuse_entries[0+1]
        self.assertTrue('$SG72513' in entry.string_ref)
        self.assertTrue('rcx' in entry.references[0].register)
        self.assertEqual(entry.data, b"U\x00S\x00E\x00R\x00P\x00R\x00O\x00F\x00I\x00L\x00E\x00\x00\x00")
        self.assertEqual(entry.addr, 0)
        self.assertEqual(7, len(entry.references[0].placeholder))  # needs to be 7!

        entry = data_reuse_entries[1+1]
        self.assertTrue('$SG72514' in entry.string_ref)


    def test_data_reuse_fixup(self):
        asm_in = "tests/data/data_reuse_pre_fixup.asm"
        asm_text = file_readall_text(asm_in)
        
        injectable = Injectable("fake.exe")
        injectable.add_datareuse_fixup(DataReuseEntry("supermega_payload"))
        settings: Settings = Settings()
        settings.payload_location = PayloadLocation.DATA
        asm_text_lines = parse_asm_text_file(injectable, asm_text, settings)

        # why -1 -1??
        self.assertTrue("\tDB " in asm_text_lines[108-1-1])
        self.assertFalse("OFFSET FLAT:$SG" in asm_text_lines[108-1-1])
        
