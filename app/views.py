from flask import Blueprint, current_app, flash, request, redirect, url_for, render_template, send_file, make_response, session, escape
from werkzeug.utils import secure_filename
import os
import logging
import io
from typing import List, Tuple
from datetime import date
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer, HexdumpLexer
from pygments.formatters import HtmlFormatter
import difflib
from ansi2html import Ansi2HTMLConverter

from config import config
from model.settings import Settings
from model.defs import *
from supermega import start

views = Blueprint('views', __name__)

conv = Ansi2HTMLConverter()


@views.route("/")
def index():
    return render_template('index.html')


@views.route("/inject", methods=['GET', 'POST'])
def inject():
    config.load()
    settings = Settings()

    settings.payload_path = "app/upload/shellcode/" + request.form['shellcode']
    settings.inject_exe_in = "app/upload/exe/" + request.form['exe']
    settings.inject_exe_out = "app/upload/infected/" + request.form['exe'] + ".injected"

    source_style = request.form['source_style']
    settings.source_style = SourceStyle[source_style]

    alloc_style = request.form['alloc_style']
    settings.alloc_style = AllocStyle[alloc_style]

    decoder_style = request.form['decoder_style']
    settings.decoder_style = DecoderStyle[decoder_style]

    exec_style = request.form['exec_style']
    settings.exec_style = ExecStyle[exec_style]

    inject_style = request.form['inject_style']
    settings.inject_style = InjectStyle[inject_style]
        
    print(str(settings))
    start(settings)

    return render_template('inject.html')


@views.route("/build")
def build():
    exes = []
    for file in os.listdir("app/upload/exe"):
        exes.append(file)

    shellcodes = []
    for file in os.listdir("app/upload/shellcode"):
        shellcodes.append(file)

    sourcestyles = [(color.name, color.value) for color in SourceStyle]
    allocstyles = [(color.name, color.value) for color in AllocStyle]
    decoderstyles = [(color.name, color.value) for color in DecoderStyle]
    execstyles = [(color.name, color.value) for color in ExecStyle]
    injectstyles = [(color.name, color.value) for color in InjectStyle]

    return render_template('build.html', 
        exes=exes,
        shellcodes=shellcodes,
        sourcestyles=sourcestyles,
        allocstyles=allocstyles,
        decoderstyles=decoderstyles,
        execstyles=execstyles,
        injectstyles=injectstyles,
    )


@views.route("/project")
def project():
    log_files = []

    id = 0
    asm_a = ""  # for diff
    asm_b = ""
    for file in os.listdir("logs"):
        if file.startswith("."):
            continue
        print("Handle: ", file)

        with open(os.path.join("logs", file), "r") as f:
            if file.endswith(".bin"):
                continue
            data = f.read()

            if 'main_c' in file:
                data = highlight(data, CLexer(), HtmlFormatter(full=False))
            elif '_asm_' in file:
                # handle special cases
                if '_orig' in file:
                    asm_a = data
                if '_updated' in file:
                    asm_b = data
                data = highlight(data, NasmLexer(), HtmlFormatter(full=False))
            elif '_shc' in file:
                if '.txt' in file:
                    # skip it
                    continue
                if '.ascii' in file:
                    data = conv.convert(data, full=False)
                if '.hex' in file:
                    data = escape(data)
                    #data = highlight(data, HexdumpLexer(), HtmlFormatter(full=False))
            elif '.log' in file:
                data = escape(data)
            else:
                data = escape(data)

            entry = {
                "name": file,
                "id": str(id),
                "content": data,
            }
            log_files.append(entry)
            id += 1

            # more
            if asm_a != "" and asm_b != "":
                # do the diff from the content of the two files
                a = asm_a.splitlines()
                b = asm_b.splitlines()
                diff_generator = difflib.unified_diff(a, b, lineterm='')
                diff_string = '\n'.join(diff_generator)
                diff_l = highlight(diff_string, DiffLexer(), HtmlFormatter(full=False))
                entry = {
                    "name": "Summary: ASM Diff".format(),
                    "id": str(id),
                    "content": diff_l,
                }
                log_files.append(entry)
                id += 1
                #asm_a = ""
                asm_b = ""


    return render_template('project.html', 
        log_files=log_files
    )
