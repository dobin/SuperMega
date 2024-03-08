from flask import Blueprint, current_app, flash, request, redirect, url_for, render_template, send_file, make_response, session, escape
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer, HexdumpLexer
from pygments.formatters import HtmlFormatter
import difflib
from ansi2html import Ansi2HTMLConverter

from config import config
from model.settings import Settings
from model.defs import *
from supermega import start
from app.storage import storage, Project

views = Blueprint('views', __name__)

conv = Ansi2HTMLConverter()
config.load()


@views.route("/")
def index():
    print(storage.data)
    return render_template('index.html', data=storage.data)


@views.route("/project/<name>")
def project(name):
    project = storage.get_project(name)
    log_files = get_logfiles()

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

    return render_template('project.html', 
        project_name = name,
        project=project, 
        
        exes=exes,
        shellcodes=shellcodes,
        sourcestyles=sourcestyles,
        allocstyles=allocstyles,
        decoderstyles=decoderstyles,
        execstyles=execstyles,
        injectstyles=injectstyles,

        log_files=log_files,
        )


@views.route("/add_project", methods=['POST', 'GET'])
def add_project():
    if request.method == 'POST':
        settings = Settings()

        project_name = request.form['project_name']

        settings.payload_path = "app/upload/shellcode/" + request.form['shellcode']
        if request.form['shellcode'] == "createfile.bin":
            settings.verify = True
            settings.try_start_final_infected_exe = False

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
        
        if storage.get_project(project_name) != None:
            project = storage.get_project(project_name)
            project.settings = settings
        else:
            project = Project(project_name, settings)
            project.settings = settings
            settings.project_name = project_name
            storage.add_project(project)
        storage.save_data()
        return redirect("/project/{}".format(project_name), code=302)
    
    else: # GET
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

        return render_template('project_add_get.html', 
            exes=exes,
            shellcodes=shellcodes,
            sourcestyles=sourcestyles,
            allocstyles=allocstyles,
            decoderstyles=decoderstyles,
            execstyles=execstyles,
            injectstyles=injectstyles,
        )


@views.route("/start_project", methods=['POST', 'GET'])
def start_project():
    #project_name = request.args.get('project_name')
    project_name = request.form.get('project_name')
    try_start = request.form.get('try_start')
    if try_start != None:
        try_start = True
    else:
        try_start = False
    project = storage.get_project(project_name)
    project.settings.try_start_final_infected_exe = try_start
    start(project.settings)
    return redirect("/project/{}".format(project_name), code=302)


def get_logfiles():
    log_files = []
    id = 0
    asm_a = ""  # for diff
    asm_b = ""
    for file in os.listdir(f"{logs_dir}/"):
        if file.startswith("."):
            continue

        with open(os.path.join(f"{logs_dir}/", file), "r") as f:
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
            elif '.ascii' in file:
                data = conv.convert(data, full=False)
            elif '.txt' in file:
                continue # skip it 
            elif '.hex' in file:
                continue # skip it 
                #data = escape(data)
                #data = highlight(data, HexdumpLexer(), HtmlFormatter(full=False))
            elif '.log' in file:
                data = conv.convert(data, full=False)
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
    return log_files