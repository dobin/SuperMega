from enum import Enum


class FilePath(str):
    pass


class AllocStyle(Enum):
    RWX = "rwx_1"
    #RW_X = "rw_x"
    #REUSE = "reuse"

class ExecStyle(Enum):
    CALL = "direct_1",
    #JMP = 2,
    #FIBER = 3,

class DecoderStyle(Enum):
    PLAIN_1 = "plain_1"
    XOR_1 = "xor_1"

class DataRefStyle(Enum):
    APPEND = 1

#class InjectStyle(Enum):
    
class SourceStyle(Enum):
    peb_walk = 1
    iat_reuse = 2

