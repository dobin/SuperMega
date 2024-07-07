import logging
from model.defs import *

logger = logging.getLogger("Views")


class Settings():
    def __init__(self, project_name: str = "default"):
        self.project_name = project_name
        self.payload_path: FilePath = ""

        # Settings
        self.carrier_name: str = ""
        self.decoder_style: str = "xor_2"
        self.short_call_patching: bool = False

        self.plugin_antiemulation = "none"
        self.plugin_decoy = "none"
        self.plugin_guardrail = "none"
        self.plugin_guardrail_data = "C:\\Users\\"
        self.plugin_virtualprotect = "standard"
        self.plugin_virtualprotect_data = ""

        self.dllfunc: str = ""  # For DLL injection

        # Anti-debugging
        self.sir_iteration_count: int = 5
        self.sir_alloc_count: int = 100

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
        self.fix_missing_iat = True
        self.patch_show_window = True
        self.payload_location = PayloadLocation.DATA

        # directories and filenames
        self.main_dir = "{}{}/".format(PATH_WEB_PROJECT, self.project_name)
        self.main_c_path = self.main_dir + "main.c"
        self.main_asm_path = self.main_dir + "main.asm"
        self.main_exe_path = self.main_dir + "main.exe"
        self.main_shc_path = self.main_dir + "main.bin"
        self.inject_exe_out = "{}{}".format(
            self.main_dir, os.path.basename(self.inject_exe_in).replace(".exe", ".infected.exe"))

    def init_payload_injectable(self, shellcode, injectable, dll_func):
        self.payload_path = PATH_SHELLCODES + shellcode
        if shellcode == "createfile.bin":
            self.verify = True
            self.try_start_final_infected_exe = False
        else:
            self.cleanup_files_on_exit = False
            
        self.inject_exe_in = injectable
        self.inject_exe_out = "{}{}".format(
            self.main_dir,
            os.path.basename(self.inject_exe_in).replace(".exe", ".infected.exe")
        )

        self.dllfunc = dll_func