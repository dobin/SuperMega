from jinja2 import Template
import shutil
import logging

from helper import *
from observer import observer
from model.defs import *
from model.settings import Settings

logger = logging.getLogger("Assembler")


def create_c_from_template(settings: Settings, payload_len: int):
    logger.info("--[ Create C from template")
    plugin_decoder = ""

    # Decoder
    filepath_decoder = PATH_DECODER + "{}.c".format(settings.decoder_style.value)
    with open(filepath_decoder, "r", encoding='utf-8') as file:
        plugin_decoder = file.read()
        plugin_decoder = Template(plugin_decoder).render({
            'PAYLOAD_LEN': payload_len,
            'XOR_KEY': config.xor_key,
        })

    # C Template: peb_walk
    if settings.source_style == SourceStyle.peb_walk:
        with open(settings.template_path, 'r', encoding='utf-8') as file:
            template_content = file.read()
            observer.add_text_file("main_c_template", template_content)

        template = Template(template_content)
        rendered_template = template.render({
            'plugin_decoder': plugin_decoder,
            'PAYLOAD_LEN': payload_len,
        })
        with open(settings.main_c_path, "w", encoding='utf-8') as file:
            file.write(rendered_template)
            observer.add_text_file("main_c_rendered", rendered_template)

    # C Template: iat_reuse
    elif settings.source_style == SourceStyle.iat_reuse:
        with open(PATH_IAT_REUSE + "template.c", 'r', encoding='utf-8') as file:
            template_content = file.read()
            observer.add_text_file("main_c_template", template_content)
        template = Template(template_content)
        rendered_template = template.render({
            'plugin_decoder': plugin_decoder,
            'PAYLOAD_LEN': payload_len,
        })
        with open(settings.main_c_path, "w", encoding='utf-8') as file:
            file.write(rendered_template)
            observer.add_text_file("main_c_rendered", rendered_template)

    else:
        raise Exception("Invalid source style: {}".format(settings.source_style))
