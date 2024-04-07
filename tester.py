from typing import Dict

from helper import *
from config import config
from model.defs import *

from model.settings import Settings
from log import setup_logging
from supermega import start


def main():
    logger.info("Super Mega Tester")
    config.load()

    settings = Settings()
    settings.payload_path =  PATH_SHELLCODES + "createfile.bin"
    settings.verify = True
    settings.try_start_final_infected_exe = False
    
    # 7z, peb-walk, change-entrypoint
    settings.source_style = FunctionInvokeStyle.peb_walk
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "7z.exe"
    settings.inject_exe_out = PATH_EXES + "7z.verify.exe"
    if start(settings) != 0:
        print("Error")
        return 1

    # 7z, peb-walk, hijack
    settings.source_style = FunctionInvokeStyle.peb_walk
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "7z.exe"
    settings.inject_exe_out = PATH_EXES + "7z.verify.exe"
    if start(settings) != 0:
        print("Error")
        return 1

    # procexp, iat-reuse, change-entrypoint
    settings.source_style = FunctionInvokeStyle.iat_reuse
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")
        return 1

    # procexp, iat-reuse, change-entrypoint
    settings.source_style = FunctionInvokeStyle.iat_reuse
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")
        return 1


if __name__ == "__main__":
    setup_logging(level=logging.WARN)
    main()
