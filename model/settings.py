from model.defs import *


class Settings():
    def __init__(self):
        self.payload_path: FilePath = ""

        # Settings
        self.source_style: SourceStyle = SourceStyle.peb_walk
        self.alloc_style: AllocStyle = AllocStyle.RWX
        self.exec_style: ExecStyle = ExecStyle.CALL
        self.decoder_style: DecoderStyle = DecoderStyle.XOR_1
        self.dataref_style: DataRefStyle = DataRefStyle.APPEND
        self.short_call_patching: bool = False

        # Injectable
        self.inject_mode: int = 2
        self.inject_exe_in: FilePath = ""
        self.inject_exe_out: FilePath = ""

        # Debug
        self.show_command_output = False
        self.verify: bool = False
        self.try_start_final_infected_exe: bool = False
        self.cleanup_files_on_start: bool = True
        self.cleanup_files_on_exit: bool = True
        self.generate_asm_from_c: bool = True
        self.generate_shc_from_asm: bool = True

