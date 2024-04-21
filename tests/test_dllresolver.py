from typing import List
import unittest

from model.defs import *
from pe.superpe import SuperPe

from pe.dllresolver import *


class DllResolverTest(unittest.TestCase):
    
    def test_dllresolver(self):
        filename = "data/binary/exes/7z.exe"
        superpe = SuperPe(filename)

        self.assertTrue(all_dll_exist(superpe))

        dlls = resolve_dlls(superpe)
        self.assertEqual(len(dlls), 5)

        dlls = unresolved_dlls(superpe)
        self.assertEqual(len(dlls), 0)

        
