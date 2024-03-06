from enum import Enum
import os

class FilePath(str):
    pass

# with data/shellcodes/createfile.bin
VerifyFilename: FilePath = r'C:\Temp\a'

# Correlated with real template files
# in data/plugins/

class AllocStyle(Enum):
    RWX = "rwx_1"
    #RW_X = "rw_x"
    #REUSE = "reuse"

class DecoderStyle(Enum):
    PLAIN_1 = "plain_1"
    XOR_1 = "xor_1"

class ExecStyle(Enum):
    CALL = "direct_1"
    #JMP = "jump",
    #FIBER = "fiber",

class DataRefStyle(Enum):
    APPEND = 1


class InjectStyle(Enum):
    ChangeEntryPoint = "change AddressOfEntryPoint"
    BackdoorCallInstr = "hijack branching instruction at Original Entry Point (jmp, call, ...)"
    
class SourceStyle(Enum):
    peb_walk = "peb_walk"
    iat_reuse = "iat_reuse"


    
class PeRelocEntry():
    def __init__(self, rva: int, base_rva: int, type: str):
        self.rva: int = rva
        self.base_rva: int = base_rva
        self.offset: int = rva - base_rva
        self.type: str = type


class IatEntry():
    def __init__(self, dll_name: str, func_name: str, iat_vaddr: int):
        self.dll_name: str = dll_name
        self.func_name: str = func_name
        self.iat_vaddr: int = iat_vaddr


# no slash at end
build_dir = "working/build"
logs_dir = "working/logs"

main_c_file = os.path.join(build_dir, "main.c")
main_asm_file = os.path.join(build_dir, "main.asm")
main_exe_file = os.path.join(build_dir, "main.exe")
main_shc_file = os.path.join(build_dir, "main.bin")