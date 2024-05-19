from jinja2 import Template
import shutil
import logging
from typing import List

from helper import *
from observer import observer
from model.defs import *
from model.settings import Settings

logger = logging.getLogger("Assembler")


def get_template_names() -> List[str]:
    templates = []
    for filename in os.listdir(PATH_CARRIER):
        if filename.startswith("."):
            continue
        if filename == "common" or filename == "decoder":
            continue
        templates.append(filename)
    return templates


def create_c_from_template(settings: Settings, payload_len: int):
    logger.info("--( Create C from template: {} -> {}".format(
        PATH_DECODER, settings.main_c_path))
    plugin_decoder = ""

    # Decoder
    filepath_decoder = PATH_DECODER + "{}.c".format(settings.decoder_style.value)
    with open(filepath_decoder, "r", encoding='utf-8') as file:
        plugin_decoder = file.read()
        plugin_decoder = Template(plugin_decoder).render({
            'PAYLOAD_LEN': payload_len,
            'XOR_KEY': config.xor_key,
        })

    # Choose correct template
    dirpath = PATH_CARRIER + settings.carrier_name + "/template.c"
    with open(dirpath, 'r', encoding='utf-8') as file:
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
