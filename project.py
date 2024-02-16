from model import *
from defs import *


class Project():
    def __init__(self):
        # User, generating normally
        self.payload: FilePath = ""

        self.source_style: SourceStyle = SourceStyle.peb_walk
        self.alloc_style: AllocStyle = AllocStyle.RWX
        self.exec_style: ExecStyle = ExecStyle.CALL
        self.decoder_style: DecoderStyle = DecoderStyle.PLAIN_1
        self.dataref_style: DataRefStyle = DataRefStyle.APPEND

        self.inject: bool = False
        self.inject_mode: str = "1,1"
        self.inject_exe_in: FilePath = ""
        self.inject_exe_out: FilePath = ""
        self.exe_capabilities: ExeCapabilities = None

        # debug
        self.show_command_output = False
        self.verify: bool = False

        self.try_start_loader_shellcode: bool = False
        self.try_start_final_shellcode: bool = False
        self.try_start_final_infected_exe: bool = False

        self.cleanup_files_on_start: bool = True
        self.cleanup_files_on_exit: bool = True

        self.generate_asm_from_c: bool = True
        self.generate_shc_from_asm: bool = True

        self.verify_filename: FilePath = r'C:\Temp\a'
        

project = Project()
