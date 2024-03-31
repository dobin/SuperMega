from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, escape, jsonify
from threading import Thread
import os
import logging
from typing import List, Tuple
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer, HexdumpLexer
from pygments.formatters import HtmlFormatter
import difflib
import subprocess
from ansi2html import Ansi2HTMLConverter

from observer import observer
from config import config
from model.settings import Settings
from model.defs import *
from supermega import start
from app.storage import storage, WebProject
from sender import scannerDetectsBytes
from phases.injector import verify_injected_exe
from helper import run_process_checkret
from model.project import prepare_project

logger = logging.getLogger("ViewsProjects")

views_project = Blueprint('views_project', __name__)

conv = Ansi2HTMLConverter()
config.load()
thread_running = False


@views_project.route("/projects")
def projects_route():
    projects = storage.get_projects()
    return render_template('projects.html', projects=projects)


@views_project.route("/project/<name>")
def project(name):
    project = storage.get_project(name)
    if project == None:
        return redirect("/projects", code=302)
    log_files = get_logfiles(project.settings.main_dir)

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


@views_project.route("/project_add", methods=['POST', 'GET'])
def add_project():
    if request.method == 'POST':
        settings = Settings()

        project_name = request.form['project_name']
        comment = request.form['comment']

        settings.payload_path = PATH_SHELLCODES + request.form['shellcode']
        if request.form['shellcode'] == "createfile.bin":
            settings.verify = True
            settings.try_start_final_infected_exe = False
        else:
            settings.cleanup_files_on_exit = False

        settings.inject_exe_in = PATH_EXES + request.form['exe']
        settings.inject_exe_out = PATH_EXES + request.form['exe'].replace(".exe", ".infected.exe")

        source_style = request.form['source_style']
        settings.source_style = SourceStyle[source_style]

        alloc_style = request.form['alloc_style']
        settings.alloc_style = AllocStyle[alloc_style]

        decoder_style = request.form['decoder_style']
        settings.decoder_style = DecoderStyle[decoder_style]

        if storage.get_project(project_name) != None:
            # overwrite project
            project = storage.get_project(project_name)
            project.settings = settings
            project.comment = comment
            storage.save_project(project)
        else:
            # add new project
            project = WebProject(project_name, settings)
            project.comment = comment
            storage.add_project(project)

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


def supermega_thread(settings: Settings):
    global thread_running
    start(settings)
    thread_running = False


@views_project.route("/project/<project_name>/build", methods=['POST', 'GET'])
def build_project(project_name):
    global thread_running

    project = storage.get_project(project_name)
    project.settings.try_start_final_infected_exe = False
    prepare_project(project_name, project.settings)
    thread = Thread(target=supermega_thread, args=(project.settings, ))
    thread.start()
    thread_running = True

    return redirect("/project/{}/status".format(project_name), code=302)


@views_project.route("/project/<project_name>/status")
def status_project(project_name):
    global thread_running
    if thread_running:
        return render_template('status_project.html', 
            project_name=project_name,
            logdata = "\n".join(observer.get_logs()))
    else:
        return redirect("/project/{}".format(project_name), code=302)


@views_project.route("/project/<project_name>/exec", methods=['POST', 'GET'])
def start_project(project_name):
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


def get_logfiles(directory):
    log_files = []
    id = 0
    asm_a = ""  # for diff
    asm_b = ""
    for file in os.listdir(f"{directory}/"):
        if file.startswith("."):
            continue
        if not file.startswith("log-"):
            continue
        if file.endswith(".bin"):
            continue

        with open(os.path.join(f"{directory}/", file), "r") as f:
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