import logging
from model.defs import *

logger = logging.getLogger("Views")


class Settings():
    def __init__(self):
        self.payload_path: FilePath = ""

        # Settings
        self.source_style: FunctionInvokeStyle = FunctionInvokeStyle.peb_walk
        self.decoder_style: DecoderStyle = DecoderStyle.XOR_1
        self.short_call_patching: bool = False

        self.dllfunc: str = ""  # For DLL injection

        # Injectable
        self.carrier_invoke_style: CarrierInvokeStyle = CarrierInvokeStyle.BackdoorCallInstr
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

        # More
        self.fix_missing_iat = False
        self.payload_location = PayloadLocation.CODE


    def prep_web(self, project_name):
        self.main_dir = "{}{}/".format(PATH_WEB_PROJECT, project_name)
        self.template_path = self.main_dir + "template.c"
        self.main_c_path = self.main_dir + "main.c"
        self.main_asm_path = self.main_dir + "main.asm"
        self.main_exe_path = self.main_dir + "main.exe"
        self.main_shc_path = self.main_dir + "main.bin"
        self.inject_exe_out = "{}{}".format(
            self.main_dir, os.path.basename(self.inject_exe_in).replace(".exe", ".infected.exe"))
