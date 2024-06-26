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
    logger.info("-( Create C from template: {} -> {}".format(
        PATH_DECODER, settings.main_c_path))
    plugin_decoder = ""

    # Plugin: VirtualAlloc
    filepath_virtualprotect = PATH_VIRTUALPROTECT + "{}.c".format(
        settings.plugin_virtualprotect)
    with open(filepath_virtualprotect, "r", encoding='utf-8') as file:
        plugin_virtualprotect = file.read()
        plugin_virtualprotect = Template(plugin_virtualprotect).render({
            'virtualprotect_data': settings.plugin_virtualprotect_data,
        })

    # Plugin: Execution Guardrails
    filepath_guardrails = PATH_GUARDRAILS + "{}.c".format(
        settings.plugin_guardrail)
    with open(filepath_guardrails, "r", encoding='utf-8') as file:
        plugin_guardrails = file.read()
        plugin_guardrails = Template(plugin_guardrails).render({
            'guardrail_data': settings.plugin_guardrail_data,
        })

    # Plugin: Decoder
    filepath_decoder = PATH_DECODER + "{}.c".format(
        settings.decoder_style)
    with open(filepath_decoder, "r", encoding='utf-8') as file:
        plugin_decoder = file.read()
        plugin_decoder = Template(plugin_decoder).render({
            'PAYLOAD_LEN': payload_len,
            'XOR_KEY': config.xor_key,
            'XOR_KEY2': ascii_to_hex_bytes(config.xor_key2),
        })

    # Plugin: Anti-Emulation
    filepath_antiemulation = PATH_ANTIEMULATION + "{}.c".format(
        settings.plugin_antiemulation)
    with open(filepath_antiemulation, "r", encoding='utf-8') as file:
        sir_iteration_count = 5
        sir_alloc_count = int(config.get("sir_target_mem") / payload_len)+1
        # if too large, compiler will add a __checkstk dependency
        if sir_alloc_count > 256:
            sir_alloc_count = 256
        logging.info("   AntiEmulation target: iterations: {} alloc: {}".format(
            sir_iteration_count, sir_alloc_count)
        )

        plugin_antiemualation = file.read()
        plugin_antiemualation = Template(plugin_antiemualation).render({
            'PAYLOAD_LEN': payload_len,
            'SIR_ALLOC_COUNT': sir_alloc_count,
            'SIR_ITERATION_COUNT': sir_iteration_count,
        })

    # Plugin: Decoy
    filepath_decoy = PATH_DECOY + "{}.c".format(
        settings.plugin_decoy)
    with open(filepath_decoy, "r", encoding='utf-8') as file:
        plugin_decoy = file.read()

    # Choose template
    dirpath = PATH_CARRIER + settings.carrier_name + "/template.c"
    with open(dirpath, 'r', encoding='utf-8') as file:
        template_content = file.read()
        observer.add_text_file("main_c_template", template_content)
    # Render template
    template = Template(template_content)
    rendered_template = template.render({
        'plugin_decoder': plugin_decoder,
        'plugin_antiemulation': plugin_antiemualation,
        'plugin_decoy': plugin_decoy,
        'plugin_executionguardrail': plugin_guardrails,
        'PAYLOAD_LEN': payload_len,
        'plugin_virtualprotect': plugin_virtualprotect,
    })
    with open(settings.main_c_path, "w", encoding='utf-8') as file:
        file.write(rendered_template)
        observer.add_text_file("main_c_rendered", rendered_template)
