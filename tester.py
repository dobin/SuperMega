from typing import Dict, List

from helper import *
from config import config
from model.defs import *

from model.settings import Settings
from log import setup_logging
from supermega import start
from model.project import prepare_project


def main():
    logger.info("Super Mega Tester: " + os.path.dirname(VerifyFilename))
    config.load()

    if not os.path.exists(os.path.dirname(VerifyFilename)):
        print("{} directory does not exist".format(os.path.dirname(VerifyFilename)))
        return

    test_dll_loader()
    test_exe_code()
    test_exe_data()
    #test_dll_code()
    #test_dll_data()


def test_dll_loader():
    print("Testing: DLL Loader")
    settings = Settings("unittest")
    settings.payload_path = PATH_SHELLCODES + "createfile.dll"
    settings.verify = True
    settings.try_start_final_infected_exe = False
    settings.payload_location = PayloadLocation.CODE  

    print("Test DLL Loader 1/2: procexp, backdoor main, dll loader alloc")
    settings.carrier_name = "dll_loader_alloc"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")

    print("Test DLL Loader 2/2: procexp, backdoor main, dll loader change")
    settings.carrier_name = "dll_loader_change"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")


def test_exe_code():
    print("Testing: EXEs: Inject payload into .text")
    settings = Settings("unittest")
    settings.payload_path = PATH_SHELLCODES + "createfile.bin"
    settings.verify = True
    settings.try_start_final_infected_exe = False
    settings.payload_location = PayloadLocation.CODE
    
    # 7z, peb-walk, change-entrypoint
    print("Test EXE 1/4: 7z, peb-walk, change-entrypoint")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "7z.exe"
    settings.inject_exe_out = PATH_EXES + "7z.verify.exe"
    if start(settings) != 0:
        print("Error")

    # 7z, peb-walk, hijack
    print("Test EXE 2/4: 7z, peb-walk, hijack main")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "7z.exe"
    settings.inject_exe_out = PATH_EXES + "7z.verify.exe"
    if start(settings) != 0:
        print("Error")

    # procexp, iat-reuse, change-entrypoint
    print("Test EXE 3/4: procexp, iat-reuse, change-entrypoint")
    settings.carrier_name = "alloc_rw_rwx"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")

    # procexp, iat-reuse, backdoor
    print("Test EXE 4/4: procexp, iat-reuse, backdoor")
    settings.carrier_name = "alloc_rw_rwx"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")


def test_exe_data():
    print("Testing: EXEs: Inject into .data")
    settings = Settings("unittest")
    settings.payload_path = PATH_SHELLCODES + "createfile.bin"
    settings.verify = True
    settings.try_start_final_infected_exe = False
    settings.payload_location = PayloadLocation.DATA
    
    # 7z, peb-walk, change-entrypoint
    print("Test EXE 1/4: 7z, peb-walk, change-entrypoint")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "7z.exe"
    settings.inject_exe_out = PATH_EXES + "7z.verify.exe"
    if start(settings) != 0:
        print("Error")

    # 7z, peb-walk, hijack
    print("Test EXE 2/4: 7z, peb-walk, hijack main")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "7z.exe"
    settings.inject_exe_out = PATH_EXES + "7z.verify.exe"
    if start(settings) != 0:
        print("Error")

    # procexp, iat-reuse, change-entrypoint
    print("Test EXE 3/4: procexp, iat-reuse, change-entrypoint")
    settings.carrier_name = "alloc_rw_rwx"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")

    # procexp, iat-reuse, backdoor
    print("Test EXE 4/4: procexp, iat-reuse, backdoor")
    settings.carrier_name = "alloc_rw_rwx"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "procexp64.exe"
    settings.inject_exe_out = PATH_EXES + "procexp64.verify.exe"
    if start(settings) != 0:
        print("Error")


def test_dll_code():
    print("Testing: DLLs code")
    settings = Settings("unittest")
    settings.payload_path = PATH_SHELLCODES + "createfile.bin"
    settings.verify = True
    settings.try_start_final_infected_exe = False
    settings.payload_location = PayloadLocation.CODE
    
    print("Test DLL 1/6: libbz2-1.dll, peb-walk, change-entrypoint dllMain (func=None)")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")

    print("Test DLL 2/6: libbz2-1.dll, peb-walk, hijack dllMain (func=None)")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")

    print("Test DLL 3/6: libbz2-1.dll, peb-walk, change-entrypoint, func=BZ2_bzDecompress")
    settings.dllfunc = "BZ2_bzDecompress"
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")

    print("Test DLL 4/6: libbz2-1.dll, peb-walk, hijack main, func=BZ2_bzdopen")
    settings.dllfunc = "BZ2_bzdopen"
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")


def test_dll_data():
    print("Testing: DLLs data")
    settings = Settings("unittest")
    settings.payload_path = PATH_SHELLCODES + "createfile.bin"
    settings.verify = True
    settings.try_start_final_infected_exe = False
    settings.payload_location = PayloadLocation.DATA
    
    print("Test DLL 1/6: libbz2-1.dll, peb-walk, change-entrypoint dllMain (func=None)")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")

    print("Test DLL 2/6: libbz2-1.dll, peb-walk, hijack dllMain (func=None)")
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")

    print("Test DLL 3/6: libbz2-1.dll, peb-walk, change-entrypoint, func=BZ2_bzDecompress")
    settings.dllfunc = "BZ2_bzDecompress"
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")

    print("Test DLL 4/6: libbz2-1.dll, peb-walk, hijack main, func=BZ2_bzdopen")
    settings.dllfunc = "BZ2_bzdopen"
    settings.carrier_name = "peb_walk"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")
    

def dll_iat_reuse():
    # procexp, iat-reuse, change-entrypoint
    print("Test: libbz2-1.dll, iat-reuse, change-entrypoint")
    settings.carrier_name = "iat_reuse"
    settings.carrier_invoke_style = CarrierInvokeStyle.ChangeEntryPoint
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")
        return 1

    # procexp, iat-reuse, backdoor
    print("Test: libbz2-1.dll, iat-reuse, backdoor")
    settings.carrier_name = "iat_reuse"
    settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorCallInstr
    settings.inject_exe_in = PATH_EXES + "libbz2-1.dll"
    settings.inject_exe_out = PATH_EXES + "libbz2-1.verify.dll"
    if start(settings) != 0:
        print("Error")
        return 1
    # DLL


if __name__ == "__main__":
    #setup_logging(level=logging.INFO)
    setup_logging(level=logging.WARNING)
    main()
