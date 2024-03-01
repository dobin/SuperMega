from jinja2 import Template
import pprint
import shutil
import logging

from helper import *
from observer import observer
from model.defs import *

use_templates = True
logger = logging.getLogger("Assembler")


# INPUT:
#   data/plugins/
#   data/source/
#
# Output:
#   build/main.c
#   build/*.h
def create_c_from_template(
    source_style: SourceStyle, 
    alloc_style: AllocStyle, 
    exec_style: ExecStyle,
    decoder_style: DecoderStyle,
    payload_len: int,
):
    plugin_allocator = ""
    plugin_decoder = ""
    plugin_executor = ""

    logger.info("--[ Create C from template")
    logger.warn("---[ {} Loader modules = Alloc: {}  Decoder: {}  Exec: {}".format(
        source_style.value, alloc_style.value, decoder_style.value, exec_style.value
    ))

    filepath = "data/plugins/allocator/{}.c".format(alloc_style.value)
    with open(filepath, "r", encoding='utf-8') as file:
        plugin_allocator = file.read()
        plugin_allocator = Template(plugin_allocator).render({
            'PAYLOAD_LEN': payload_len,
        })

    filepath = "data/plugins/decoder/{}.c".format(decoder_style.value)
    with open(filepath, "r", encoding='utf-8') as file:
        plugin_decoder = file.read()
        plugin_decoder = Template(plugin_decoder).render({
            'PAYLOAD_LEN': payload_len,
            'XOR_KEY': config.xor_key,
        })

    filepath = "data/plugins/executor/{}.c".format(exec_style.value)
    with open("data/plugins/executor/direct_1.c", "r", encoding='utf-8') as file:
        plugin_executor = file.read()
        plugin_executor = Template(plugin_executor).render({
            'PAYLOAD_LEN': payload_len,
        })
    
    if source_style == SourceStyle.peb_walk:
        if use_templates:
            with open("data/source/peb_walk/template.c", 'r', encoding='utf-8') as file:
                template_content = file.read()
                observer.add_text("main_c_template", template_content)

            template = Template(template_content)
            rendered_template = template.render({
                'plugin_allocator': plugin_allocator,
                'plugin_decoder': plugin_decoder,
                'plugin_executor': plugin_executor,
                'PAYLOAD_LEN': payload_len,
            })
            with open(main_c_file, "w", encoding='utf-8') as file:
                file.write(rendered_template)
                observer.add_text("main_c_rendered", rendered_template)

            # TODO PEB
            shutil.copy("data/source/peb_walk/peb_lookup.h", "build/peb_lookup.h")
        else:
            observer.add_text("main_c", file_readall_text("data/source/peb_walk/main.c"))
            shutil.copy("data/source/peb_walk/main.c", main_c_file)
            # TODO PEB
            shutil.copy("data/source/peb_walk/peb_lookup.h", "build/peb_lookup.h")

    elif source_style == SourceStyle.iat_reuse:
        if use_templates:
            with open("data/source/iat_reuse/template.c", 'r', encoding='utf-8') as file:
                template_content = file.read()
                observer.add_text("main_c_template", template_content)
            template = Template(template_content)
            rendered_template = template.render({
                'plugin_allocator': plugin_allocator,
                'plugin_decoder': plugin_decoder,
                'plugin_executor': plugin_executor,
                'PAYLOAD_LEN': payload_len,
            })
            with open(main_c_file, "w", encoding='utf-8') as file:
                file.write(rendered_template)
                observer.add_text("main_c_rendered", rendered_template)
        else:
            observer.add_text("main_c", file_readall_text("data/source/iat_reuse/main.c"))
            shutil.copy("data/source/iat_reuse/main.c", main_c_file)