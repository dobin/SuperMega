from jinja2 import Template
import pprint
import shutil

from helper import *
from config import config
from project import project
from model import *
from observer import observer

use_templates = True


# INPUT:
#   plugins/
#   source/
#
# Output:
#   build/main.c
#   build/*.h
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
            shutil.copy("source/peb_walk/peb_lookup.h", "build/peb_lookup.h")

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