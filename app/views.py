from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from threading import Thread
from werkzeug.utils import secure_filename
import os
import logging
from typing import List, Tuple
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer, HexdumpLexer
from pygments.formatters import HtmlFormatter
import difflib
from ansi2html import Ansi2HTMLConverter
import shutil
import subprocess
import time
from datetime import datetime

from observer import observer
from config import config
from model.settings import Settings
from model.defs import *
from supermega import start
from app.storage import storage, Project
from sender import scannerDetectsBytes
from phases.injector import verify_injected_exe
from phases.compiler import compile_dev
from phases.assembler import asm_to_shellcode
from helper import run_process_checkret
from log import MyLog

views = Blueprint('views', __name__)

conv = Ansi2HTMLConverter()
config.load()

thread_running = False

logger = logging.getLogger("Views")


@views.route("/")
def index():
    return render_template('index.html', data=storage.data)


@views.route("/projects")
def projects_route():
    return render_template('projects.html', data=storage.data)


@views.route("/shcdev")
def devs_route():
    data = []
    for filename in os.listdir(PATH_PAYLOAD):
        file_path = PATH_PAYLOAD + filename
        creation_time = os.path.getctime(file_path)
        readable_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
        data.append({
            "name": filename,
            "date": readable_time,
        })
    return render_template('devs.html', data=data)


@views.route("/shcdev/<name>")
def dev_route(name):
    data = []
    log = ""
    path = PATH_PAYLOAD + name
    for filename in os.listdir(path):
        filepath = path + "/" + filename
        
        creation_time = os.path.getmtime(filepath)
        readable_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
        
        info = ""
        if filename.endswith(".asm"):
            info = "text assembly (cleaned, from compiled .c)"
        elif filename.endswith(".bin"):
            info = "generated shellcode (from .exe)"
        elif filename.endswith(".c"):
            info = "input C code"
        elif filename.endswith(".exe"):
            info = "temporary shellcode holder (from .c)"
        elif filename.endswith(".log"):
            info = "log file"
            with open(path + "/" + filename, "r") as f:
                log = f.read()

            #print(log)

        data.append({
            "name": filename,
            "date": readable_time,
            "info": info,
        })

    return render_template('dev.html', 
        name=name, files=data, log=log)


@views.route("/shcdev/<name>/build")
def dev_build_route(name):

    c_in = PATH_PAYLOAD + "{}/main.c".format(name)
    asm_out = PATH_PAYLOAD + "{}/main.asm".format(name)
    build_exe = PATH_PAYLOAD + "{}/main.exe".format(name)
    shellcode_out = PATH_PAYLOAD + "{}/main.bin".format(name)
    log = PATH_PAYLOAD + "{}/main.log".format(name)

    compile_dev(c_in, asm_out)
    asm_to_shellcode(asm_out, build_exe, shellcode_out)

    with open(log, "w") as f:
        for log_line in MyLog.getlog():
            f.write("{}\n".format(log_line))

        f.write("\n\n")

        for log in observer.logs:
            f.write("{}".format(log))

    return redirect("/shcdev/{}".format(name), code=302)


@views.route("/project/<name>")
def project(name):
    project = storage.get_project(name)
    log_files = get_logfiles()

    exes = []
    for file in os.listdir(PATH_EXES):
        exes.append(file)

    shellcodes = []
    for file in os.listdir(PATH_SHELLCODES):
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
        comment = request.form['comment']

        settings.payload_path = PATH_SHELLCODES + request.form['shellcode']
        if request.form['shellcode'] == "createfile.bin":
            settings.verify = True
            settings.try_start_final_infected_exe = False

        settings.inject_exe_in = PATH_EXES + request.form['exe']
        settings.inject_exe_out = PATH_EXES + request.form['exe'].replace(".exe", ".infected.exe")

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
            # overwrite project
            project = storage.get_project(project_name)
            project.settings = settings
            project.comment = comment
        else:
            # add new project
            project = Project(project_name, settings)
            project.project_dir = PATH_WEB_PROJECT + "{}".format(project_name)
            project.project_exe = request.form['exe'].replace(".exe", ".infected.exe")
            project.settings = settings
            settings.project_name = project_name
            project.comment = comment
            storage.add_project(project)
        storage.save_data()
        return redirect("/project/{}".format(project_name), code=302)
    
    else: # GET
        exes = []
        for file in os.listdir(PATH_EXES):
            exes.append(file)

        shellcodes = []
        for file in os.listdir(PATH_SHELLCODES):
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


def supermega_thread(project: Project):
    global thread_running
    start(project.settings)
    thread_running = False

    # copy generated file to project folder
    file_basename = os.path.basename(project.settings.inject_exe_out)
    project.project_exe = file_basename
    dest = PATH_WEB_PROJECT + "{}/{}".format(project.name, file_basename)
    logger.info("Copy {} to project folder {}".format(project.settings.inject_exe_out, dest))
    shutil.copy(
        project.settings.inject_exe_out,
        dest,
    )


@views.route("/build_project", methods=['POST', 'GET'])
def build_project():
    global thread_running

    project_name = request.form.get('project_name')
    project = storage.get_project(project_name)
    project.settings.try_start_final_infected_exe = False

    thread = Thread(target=supermega_thread, args=(project, ))
    thread.start()
    thread_running = True

    return redirect("/status_project/{}".format(project_name), code=302)


@views.route("/status_project/<project_name>")
def status_project(project_name):
    global thread_running
    if thread_running:
        return render_template('status_project.html', 
            project_name=project_name,
            logdata = "asdf")
    else:
        return redirect("/project/{}".format(project_name), code=302)


@views.route("/exec_project", methods=['POST', 'GET'])
def start_project():
    project_name = request.form.get('project_name')
    project = storage.get_project(project_name)
    if project == None:
        return redirect("/", code=302)

    remote = False
    remote_arg = request.args.get('remote')
    if remote_arg == "true":
        remote = True

    no_exec = False
    no_exec_arg = request.args.get('no_exec')
    if no_exec_arg == "true":
        no_exec = True

    logger.info("--[ Exec project: {} remote: {} no_exec: {}".format(project_name, remote, no_exec))

    if remote:
        logger.info("--[ Exec {} on server {}".format(project.project_exe, config.get("avred_server")))
        filepath = "{}/{}".format(project.project_dir, project.project_exe)
        with open(filepath, "rb") as f:
            data = f.read()
        try:
            scannerDetectsBytes(data, 
                                project.project_exe, 
                                useBrotli=True, 
                                verify=project.settings.verify,
                                no_exec=no_exec)
        except Exception as e:
            logger.error(f'Error scanning: {e}')
            return jsonify({
				"exception": str(e)
			}), 500
    else:
        # Start/verify it at the end
        if project.settings.verify:
            logger.info("--[ Verify infected exe")
            exit_code = verify_injected_exe(project.settings.inject_exe_out)
        elif no_exec == False:
            logger.info("--[ Start infected exe: {}".format(project.settings.inject_exe_out))
            run_process_checkret([
                project.settings.inject_exe_out,
            ], check=False)
        elif no_exec == True:
            dirname = os.path.dirname(os.path.abspath(project.settings.inject_exe_out))
            logger.info("--[ Open folder: {}".format(dirname))
            subprocess.run(['explorer', dirname])

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