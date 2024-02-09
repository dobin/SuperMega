from model import *


class Observer():
    def __init__(self):
        self.capabilities_a: ExeCapabilities = None
        self.options: SourceStyle = None
        self.main_c: str = ""
        self.payload_asm_orig: bytes = ""
        self.payload_asm_cleanup: bytes = ""
        self.payload_asm_fixup: bytes = ""
        self.loader_shellcode: bytes = b""
        self.final_shellcode: bytes = b""

    def __str__(self):
        s = ""
        s += "{} {}\n\n".format(
            self.capabilities_a,
            self.options,)

        s += "Main: {} Payload Orig: {} Payload Cleanup: {}\n".format(
            len(self.main_c),
            len(self.payload_asm_orig),
            len(self.payload_asm_cleanup),

        )
        s += "fixup: {} loader: {} final: {}\n".format(
            len(self.payload_asm_fixup),
            len(self.loader_shellcode),
            len(self.final_shellcode),
        )
    
        return s


observer = Observer()